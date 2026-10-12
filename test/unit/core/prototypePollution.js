"use strict";

import assert from "assert";
import http from "http";
import stream from "stream";
import EventEmitter from "events";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import resolveConfig from "../../../lib/helpers/resolveConfig.js";
import httpAdapter from "../../../lib/adapters/http.js";
import defaults from "../../../lib/defaults/index.js";

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });
});

describe("Prototype pollution gadgets in request construction (CVE-2026-67316)", function () {
  const pollutedKeys = [
    "data",
    "params",
    "paramsSerializer",
    "proxy",
    "serialize",
    "encode",
    "username",
    "password",
    "entries",
  ];
  const proxyEnvKeys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"];
  let savedProxyEnv;

  function pollute(key, value) {
    Object.defineProperty(Object.prototype, key, {
      value: value,
      configurable: true,
      writable: true,
    });
  }

  function startServer(handler) {
    return new Promise(function (resolve, reject) {
      const server = http.createServer(handler);
      server.once("error", reject);
      server.listen(0, "127.0.0.1", function () {
        resolve(server);
      });
    });
  }

  function stopServer(server) {
    return new Promise(function (resolve) {
      if (!server) {
        resolve();
        return;
      }
      if (typeof server.closeAllConnections === "function") {
        server.closeAllConnections();
      }
      server.close(function () {
        resolve();
      });
    });
  }

  function startEchoServer() {
    return startServer(function (req, res) {
      let body = "";
      req.setEncoding("utf8");
      req.on("data", function (chunk) {
        body += chunk;
      });
      req.on("end", function () {
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            method: req.method,
            url: req.url,
            body: body,
            contentLength: req.headers["content-length"] === undefined ? null : req.headers["content-length"],
            authorization: req.headers.authorization === undefined ? null : req.headers.authorization,
          }),
        );
      });
    });
  }

  function serverURL(server, path) {
    return "http://127.0.0.1:" + server.address().port + (path || "/");
  }

  function getHeader(headers, name) {
    const lName = name.toLowerCase();
    const keys = Object.keys(headers);
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === lName) {
        return headers[keys[i]];
      }
    }
    return undefined;
  }

  beforeEach(function () {
    savedProxyEnv = {};
    proxyEnvKeys.forEach(function (key) {
      savedProxyEnv[key] = process.env[key];
      delete process.env[key];
    });
  });

  afterEach(function () {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
    delete Object.prototype[Symbol.iterator];
    delete Object.prototype[Symbol.toStringTag];

    proxyEnvKeys.forEach(function (key) {
      if (savedProxyEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = savedProxyEnv[key];
      }
    });
  });

  describe("utils.hasOwnInPrototypeChain / getSafeProp / isSafeIterable", function () {
    it("should ignore inherited symbol properties when validating plain Object", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-injected", "yes"];
      };
      Object.prototype[Symbol.toStringTag] = "Custom";

      assert.strictEqual(utils.isPlainObject({}), true);
      assert.strictEqual(utils.isPlainObject([]), false);
      assert.strictEqual(
        utils.isPlainObject({
          [Symbol.iterator]: function* () {
            yield ["x-own", "yes"];
          },
        }),
        false,
      );
      assert.strictEqual(utils.isPlainObject({ [Symbol.toStringTag]: "Custom" }), false);
    });

    it("should treat an object with a genuinely inherited iterator as non-plain", function () {
      const proto = Object.create(null);
      proto[Symbol.iterator] = function* () {
        yield ["x", "1"];
      };

      assert.strictEqual(utils.isPlainObject(Object.create(proto)), false);
    });

    it("should not read polluted Object.prototype iterator accessors for safe iterable checks", function () {
      let accessed = false;

      Object.defineProperty(Object.prototype, Symbol.iterator, {
        configurable: true,
        get: function () {
          accessed = true;
          throw new Error("polluted iterator accessor");
        },
      });

      assert.strictEqual(utils.isSafeIterable({}), false);
      assert.strictEqual(accessed, false);
    });

    it("should still report genuine iterables as safe", function () {
      assert.strictEqual(utils.isSafeIterable([]), true);
      assert.strictEqual(utils.isSafeIterable(new Map()), true);
      assert.strictEqual(utils.isSafeIterable({}), false);
      assert.strictEqual(utils.isSafeIterable(null), false);
    });

    it("should stop safe prototype-chain reads on cyclic Proxy prototypes", function () {
      let calls = 0;
      let proxy;
      proxy = new Proxy(
        {},
        {
          getPrototypeOf: function () {
            calls += 1;
            if (calls > 5) {
              throw new Error("cycled");
            }
            return proxy;
          },
        },
      );

      assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, "missing"), false);
      assert.strictEqual(utils.getSafeProp(proxy, "missing"), undefined);
      assert.ok(calls <= 2, "prototype chain walked " + calls + " times");
    });

    it("should honor own and template-inherited values but ignore Object.prototype ones", function () {
      pollute("username", "inherited-user");

      const template = { username: "template-user" };

      assert.strictEqual(utils.getSafeProp({ username: "own-user" }, "username"), "own-user");
      assert.strictEqual(utils.getSafeProp(Object.create(template), "username"), "template-user");
      assert.strictEqual(utils.getSafeProp({}, "username"), undefined);
      assert.strictEqual(utils.getSafeProp(null, "username"), undefined);
      assert.strictEqual(utils.getSafeProp(undefined, "username"), undefined);
    });
  });

  describe("AxiosHeaders", function () {
    it("should not use inherited Symbol.iterator as a key-value source object", function () {
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-app", "changed"];
        yield ["x-injected", "yes"];
      };

      const headers = new AxiosHeaders({
        "x-app": "safe",
      });

      assert.strictEqual(headers.get("x-app"), "safe");
      assert.strictEqual(headers.get("x-injected"), undefined);
    });

    it("should not read polluted Object.prototype Symbol.iterator accessors", function () {
      let accessed = false;

      Object.defineProperty(Object.prototype, Symbol.iterator, {
        configurable: true,
        get: function () {
          accessed = true;
          throw new Error("polluted iterator accessor");
        },
      });

      const headers = new AxiosHeaders({
        "x-app": "safe",
      });

      assert.strictEqual(headers.get("x-app"), "safe");
      assert.strictEqual(accessed, false);
    });

    it("should not consume polluted Headers-like members for non-plain header sources", function () {
      // Make every object look like a fetch Headers instance through
      // Object.prototype only: tag, iterator and entries() are all polluted.
      Object.prototype[Symbol.toStringTag] = "Headers";
      Object.prototype[Symbol.iterator] = function* () {
        yield ["x-injected", "yes"];
        yield ["authorization", "Bearer CHANGED"];
      };
      pollute("entries", function* () {
        yield ["x-injected", "yes"];
        yield ["authorization", "Bearer CHANGED"];
      });

      class HeaderBag {
        constructor() {
          this.authorization = "Bearer VALID";
        }
      }

      const fromClass = new AxiosHeaders(new HeaderBag());
      assert.strictEqual(fromClass.get("x-injected"), undefined);
      assert.notStrictEqual(fromClass.get("authorization"), "Bearer CHANGED");

      const created = Object.create({ "x-app": "safe" });
      created.authorization = "Bearer VALID";
      const fromCreate = new AxiosHeaders(created);
      assert.strictEqual(fromCreate.get("x-injected"), undefined);
      assert.notStrictEqual(fromCreate.get("authorization"), "Bearer CHANGED");
    });

    it("should still accept genuine fetch Headers instances", function () {
      if (typeof Headers !== "function") {
        this.skip();
        return;
      }

      const headers = new AxiosHeaders(new Headers([["x-a", "1"]]));

      assert.strictEqual(headers.get("x-a"), "1");
    });
  });

  describe("bodyless method data", function () {
    it("should ignore inherited data for bodyless method helpers", async function () {
      pollute("data", "inherited-body");

      await Promise.all(
        ["delete", "get", "head", "options"].map(async function (method) {
          let seenData = "unset";

          await axios[method]("/test", {
            adapter: function (config) {
              seenData = config.data;

              return Promise.resolve({
                data: null,
                status: 200,
                statusText: "OK",
                headers: {},
                config: config,
                request: {},
              });
            },
          });

          assert.strictEqual(seenData, undefined, method + " picked up an inherited body");
        }),
      );
    });

    it("should not send a polluted Object.prototype.data body with axios.get/delete over http", async function () {
      this.timeout(10000);
      const server = await startEchoServer();

      try {
        pollute("data", "INJECTED");

        const getResponse = await axios.get(serverURL(server, "/data"));
        assert.strictEqual(getResponse.data.method, "GET");
        assert.strictEqual(getResponse.data.body, "");
        assert.ok(getResponse.data.contentLength === null || getResponse.data.contentLength === "0");

        const deleteResponse = await axios.delete(serverURL(server, "/data"));
        assert.strictEqual(deleteResponse.data.method, "DELETE");
        assert.strictEqual(deleteResponse.data.body, "");
        assert.ok(deleteResponse.data.contentLength === null || deleteResponse.data.contentLength === "0");
      } finally {
        delete Object.prototype.data;
        await stopServer(server);
      }
    });

    it("should not send a polluted Object.prototype.data body when the http adapter gets a plain config", async function () {
      this.timeout(10000);
      const server = await startEchoServer();

      try {
        pollute("data", "INJECTED");

        const response = await httpAdapter({
          method: "delete",
          url: serverURL(server, "/direct"),
          headers: {},
          proxy: false,
          maxRedirects: 0,
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        });
        const data = JSON.parse(response.data);

        assert.strictEqual(data.method, "DELETE");
        assert.strictEqual(data.body, "");
        assert.ok(data.contentLength === null || data.contentLength === "0");
      } finally {
        delete Object.prototype.data;
        await stopServer(server);
      }
    });

    it("should not expose a polluted Object.prototype.data body through resolveConfig", function () {
      pollute("data", "INJECTED");

      const config = resolveConfig({ url: "/foo", method: "delete" });

      assert.strictEqual(config.data, undefined);
    });

    it("should not send a polluted Object.prototype.data body with the fetch adapter", async function () {
      if (typeof fetch !== "function") {
        this.skip();
        return;
      }

      this.timeout(10000);
      const server = await startEchoServer();

      try {
        pollute("data", "INJECTED");

        const response = await axios.delete(serverURL(server, "/fetch"), { adapter: "fetch" });

        assert.strictEqual(response.data.body, "");
      } finally {
        delete Object.prototype.data;
        await stopServer(server);
      }
    });
  });

  describe("proxy", function () {
    async function runProxyCase(request) {
      let proxyHits = 0;
      let targetHits = 0;
      let proxyServer;
      let targetServer;

      try {
        proxyServer = await startServer(function (req, res) {
          proxyHits += 1;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ via: "proxy", url: req.url }));
        });

        targetServer = await startServer(function (req, res) {
          targetHits += 1;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ via: "target", url: req.url }));
        });

        pollute("proxy", {
          protocol: "http",
          host: "127.0.0.1",
          port: proxyServer.address().port,
        });

        const data = await request(serverURL(targetServer, "/direct"));

        assert.strictEqual(proxyHits, 0);
        assert.strictEqual(targetHits, 1);
        assert.deepStrictEqual(data, { via: "target", url: "/direct" });
      } finally {
        delete Object.prototype.proxy;
        await stopServer(targetServer);
        await stopServer(proxyServer);
      }
    }

    it("should ignore inherited proxy when http adapter receives a plain config", async function () {
      this.timeout(10000);

      await runProxyCase(async function (url) {
        const response = await httpAdapter({
          method: "get",
          url: url,
          headers: {},
          maxRedirects: 0,
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        });

        return JSON.parse(response.data);
      });
    });

    it("should ignore inherited proxy for regular axios requests", async function () {
      this.timeout(10000);

      await runProxyCase(async function (url) {
        const response = await axios.get(url);

        return response.data;
      });
    });
  });

  describe("params and paramsSerializer", function () {
    it("should ignore inherited paramsSerializer when http adapter receives a plain config", async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      const server = await startEchoServer();

      try {
        pollute("paramsSerializer", function () {
          serializerInvoked = true;
          return "inherited=1";
        });

        const response = await httpAdapter({
          method: "get",
          url: serverURL(server, "/direct"),
          headers: {},
          params: { value: "a b" },
          proxy: false,
          maxRedirects: 0,
          maxContentLength: -1,
          maxBodyLength: -1,
          timeout: 0,
        });
        const data = JSON.parse(response.data);

        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(data.url, "/direct?value=a+b");
      } finally {
        delete Object.prototype.paramsSerializer;
        await stopServer(server);
      }
    });

    it("should ignore inherited paramsSerializer for regular axios requests", async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      const server = await startEchoServer();

      try {
        pollute("paramsSerializer", function () {
          serializerInvoked = true;
          return "inherited=1";
        });

        const response = await axios.get(serverURL(server, "/demo"), {
          params: { value: "a b" },
        });

        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(response.data.url, "/demo?value=a+b");
      } finally {
        delete Object.prototype.paramsSerializer;
        await stopServer(server);
      }
    });

    it("should ignore inherited paramsSerializer in resolveConfig", function () {
      let serializerInvoked = false;

      pollute("paramsSerializer", function () {
        serializerInvoked = true;
        return "inherited=1";
      });

      const config = resolveConfig({
        url: "/foo",
        params: { value: "a b" },
      });

      assert.strictEqual(config.url, "/foo?value=a+b");
      assert.strictEqual(serializerInvoked, false);
    });

    it("should ignore inherited paramsSerializer and params in getUri", function () {
      let serializerInvoked = false;

      pollute("paramsSerializer", function () {
        serializerInvoked = true;
        return "inherited=1";
      });

      assert.strictEqual(axios.getUri({ url: "/foo", params: { value: "a b" } }), "/foo?value=a+b");
      assert.strictEqual(serializerInvoked, false);

      delete Object.prototype.paramsSerializer;
      pollute("params", { injected: "yes" });

      assert.strictEqual(axios.getUri({ url: "/foo" }), "/foo");
    });

    it("should not append inherited params to requests", async function () {
      this.timeout(10000);
      const server = await startEchoServer();

      try {
        pollute("params", { injected: "yes" });

        const response = await axios.get(serverURL(server, "/demo"));
        assert.strictEqual(response.data.url, "/demo");

        assert.strictEqual(resolveConfig({ url: "/foo" }).url, "/foo");
      } finally {
        delete Object.prototype.params;
        await stopServer(server);
      }
    });
  });

  describe("nested option objects", function () {
    it("should ignore inherited serializer options in buildURL", function () {
      let serializeInvoked = false;
      let encodeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });
      pollute("encode", function () {
        encodeInvoked = true;
        return "inherited";
      });

      assert.strictEqual(buildURL("/foo", { value: "a b" }, {}), "/foo?value=a+b");
      assert.strictEqual(serializeInvoked, false);
      assert.strictEqual(encodeInvoked, false);
    });

    it("should still honor own serializer options in buildURL", function () {
      assert.strictEqual(
        buildURL("/foo", { value: "a b" }, function () {
          return "custom=1";
        }),
        "/foo?custom=1",
      );
      assert.strictEqual(
        buildURL(
          "/foo",
          { value: "a b" },
          {
            encode: function (value) {
              return value.toUpperCase();
            },
          },
        ),
        "/foo?VALUE=A B",
      );
    });

    it("should ignore inherited nested auth fields in resolveConfig", function () {
      if (typeof btoa === "undefined") {
        this.skip();
        return;
      }

      pollute("username", "inherited-user");
      pollute("password", "inherited-pass");

      const config = resolveConfig({
        url: "/foo",
        auth: {},
      });

      assert.strictEqual(config.headers.get("Authorization"), "Basic Og==");
    });

    it("should still use own nested auth fields in resolveConfig", function () {
      if (typeof btoa === "undefined") {
        this.skip();
        return;
      }

      pollute("username", "inherited-user");
      pollute("password", "inherited-pass");

      const config = resolveConfig({
        url: "/foo",
        auth: { username: "Aladdin", password: "open sesame" },
      });

      assert.strictEqual(config.headers.get("Authorization"), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    });

    it("should ignore inherited nested serializer fields in resolveConfig", function () {
      let serializeInvoked = false;
      let encodeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });
      pollute("encode", function () {
        encodeInvoked = true;
        return "inherited";
      });

      const config = resolveConfig({
        url: "/foo",
        params: { value: "a b" },
        paramsSerializer: {},
      });

      assert.strictEqual(config.url, "/foo?value=a+b");
      assert.strictEqual(serializeInvoked, false);
      assert.strictEqual(encodeInvoked, false);
    });

    it("should ignore inherited nested serializer fields in getUri", function () {
      let serializeInvoked = false;

      pollute("serialize", function () {
        serializeInvoked = true;
        return "inherited=1";
      });

      assert.strictEqual(
        axios.getUri({
          url: "/foo",
          params: { value: "a b" },
          paramsSerializer: {},
        }),
        "/foo?value=a+b",
      );
      assert.strictEqual(serializeInvoked, false);
    });

    it("should ignore inherited nested request option fields in http adapter", async function () {
      this.timeout(10000);
      const server = await startEchoServer();

      try {
        pollute("username", "inherited-user");
        pollute("password", "inherited-pass");
        pollute("serialize", function () {
          return "inherited=1";
        });

        const response = await axios.get(serverURL(server, "/demo"), {
          auth: {},
          params: { value: "a b" },
          paramsSerializer: {},
        });

        assert.strictEqual(response.data.authorization, "Basic Og==");
        assert.strictEqual(response.data.url, "/demo?value=a+b");
      } finally {
        delete Object.prototype.username;
        delete Object.prototype.password;
        delete Object.prototype.serialize;
        await stopServer(server);
      }
    });
  });

  describe("Symbol gadgets on request/response headers", function () {
    it("should not use inherited Symbol.iterator for request or response headers", async function () {
      let capturedHeaders;
      const stubTransport = {
        request: function (options, handleResponse) {
          capturedHeaders = Object.assign({}, options.headers);
          const req = new EventEmitter();
          req.write = function () {
            return true;
          };
          req.setTimeout = function () {};
          req.destroy = function () {};
          req.end = function () {
            const res = new stream.Readable({ read: function () {} });
            res.statusCode = 200;
            res.statusMessage = "OK";
            res.headers = { "x-server": "real" };
            res.rawHeaders = [];
            res.req = req;
            process.nextTick(function () {
              handleResponse(res);
              res.push(null);
            });
          };
          return req;
        },
      };

      try {
        Object.prototype[Symbol.iterator] = function* () {
          yield ["X-Injected", "yes"];
          yield ["Authorization", "Bearer CHANGED"];
        };

        const response = await axios.get("http://stub.invalid/", {
          headers: {
            Authorization: "Bearer VALID_USER_TOKEN",
            "X-App": "safe",
          },
          transport: stubTransport,
          maxRedirects: 0,
        });

        assert.ok(capturedHeaders, "transport was not invoked");
        assert.strictEqual(getHeader(capturedHeaders, "X-App"), "safe");
        assert.strictEqual(getHeader(capturedHeaders, "Authorization"), "Bearer VALID_USER_TOKEN");
        assert.strictEqual(getHeader(capturedHeaders, "X-Injected"), undefined);
        assert.strictEqual(response.headers.get("x-server"), "real");
        assert.strictEqual(response.headers.get("x-injected"), undefined);
      } finally {
        delete Object.prototype[Symbol.iterator];
      }
    });
  });

  describe("config value gadgets (CVE-2026-42033)", function () {
    const gadgetKeys = [
      "transport",
      "transformRequest",
      "transformResponse",
      "transitional",
      "validateStatus",
      "formSerializer",
      "env",
      "lookup",
      "family",
      "responseType",
      "responseEncoding",
    ];

    afterEach(function () {
      gadgetKeys.forEach(function (key) {
        delete Object.prototype[key];
      });
    });

    function ownValue(obj, key) {
      return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
    }

    function stubTransport(body, onRequest, statusCode) {
      return {
        request: function (options, handleResponse) {
          if (onRequest) {
            onRequest(options);
          }
          const req = new EventEmitter();
          req.write = function () {
            return true;
          };
          req.setTimeout = function () {};
          req.destroy = function () {};
          req.end = function () {
            const res = new stream.Readable({ read: function () {} });
            res.statusCode = statusCode || 200;
            res.statusMessage = "OK";
            res.headers = { "content-type": "application/json" };
            res.rawHeaders = [];
            res.req = req;
            process.nextTick(function () {
              handleResponse(res);
              res.push(Buffer.from(body, "utf8"));
              res.push(null);
            });
          };
          return req;
        },
      };
    }

    function captureAdapter(seen, responseBody) {
      return function (config) {
        seen.config = config;
        return Promise.resolve({
          data: responseBody === undefined ? null : responseBody,
          status: 200,
          statusText: "OK",
          headers: {},
          config: config,
          request: {},
        });
      };
    }

    describe("mergeConfig", function () {
      it("should keep own transformRequest/transformResponse when they are polluted on Object.prototype", function () {
        const safeRequest = function (data) {
          return data;
        };
        const safeResponse = function (data) {
          return data;
        };

        pollute("transformRequest", [
          function () {
            return "hijacked";
          },
        ]);
        pollute("transformResponse", [
          function () {
            return "hijacked";
          },
        ]);

        const result = mergeConfig(
          { transformRequest: [safeRequest], transformResponse: [safeResponse] },
          { url: "/a" },
        );

        assert.strictEqual(result.transformRequest.length, 1);
        assert.strictEqual(result.transformRequest[0], safeRequest);
        assert.strictEqual(result.transformResponse.length, 1);
        assert.strictEqual(result.transformResponse[0], safeResponse);
      });

      it("should keep own transport when Object.prototype.transport is polluted", function () {
        const safeRequest = function () {};

        pollute("transport", {
          request: function () {
            throw new Error("hijacked");
          },
        });

        const result = mergeConfig({ transport: { request: safeRequest } }, { url: "/a" });

        assert.strictEqual(result.transport.request, safeRequest);
      });

      it("should not merge polluted Object.prototype values into own nested options", function () {
        pollute("transitional", { injected: true, silentJSONParsing: false });

        const result = mergeConfig({}, { transitional: { forcedJSONParsing: false } });

        assert.strictEqual(result.transitional.forcedJSONParsing, false);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(result.transitional, "injected"), false);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(result.transitional, "silentJSONParsing"), false);
      });

      it("should keep own validateStatus when Object.prototype.validateStatus is polluted", function () {
        const safeValidateStatus = function (status) {
          return status >= 200 && status < 300;
        };

        pollute("validateStatus", function () {
          return true;
        });

        const result = mergeConfig({ validateStatus: safeValidateStatus }, { url: "/a" });

        assert.strictEqual(result.validateStatus, safeValidateStatus);
      });
    });

    describe("request/response transforms", function () {
      it("should not let a polluted transformResponse tamper with response data", async function () {
        const seen = {};

        pollute("transformResponse", [
          function () {
            return { role: "admin", balance: 999999 };
          },
        ]);

        const response = await axios.get("/account", {
          adapter: captureAdapter(seen, '{"role":"user","balance":100}'),
        });

        assert.deepStrictEqual(response.data, { role: "user", balance: 100 });
      });

      it("should not let a polluted transformRequest rewrite the request body", async function () {
        const seen = {};

        pollute("transformRequest", [
          function () {
            return "hijacked";
          },
        ]);

        await axios.post("/submit", { a: 1 }, { adapter: captureAdapter(seen) });

        assert.strictEqual(seen.config.data, '{"a":1}');
      });

      it("should never invoke polluted transform gadgets, not even as option validators", async function () {
        const seen = {};
        const leaked = [];

        // A gadget that passes option validation (returns true) and then
        // tampers with data / exfiltrates the config when used as a transform.
        function gadget(value, opt, opts) {
          leaked.push(opts);
          return true;
        }

        pollute("transformRequest", gadget);
        pollute("transformResponse", gadget);

        const response = await axios.post(
          "/submit",
          { a: 1 },
          {
            auth: { username: "svc_account", password: "hunter2" },
            adapter: captureAdapter(seen, '{"ok":true}'),
          },
        );

        assert.strictEqual(leaked.length, 0, "polluted gadget was invoked");
        assert.strictEqual(seen.config.data, '{"a":1}');
        assert.deepStrictEqual(response.data, { ok: true });
      });

      it("should not use a polluted formSerializer for urlencoded bodies", async function () {
        const seen = {};
        let visitorInvoked = false;

        pollute("formSerializer", {
          visitor: function () {
            visitorInvoked = true;
            this.append("injected", "yes");
            return false;
          },
        });

        await axios.post(
          "/form",
          { a: "1" },
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            adapter: captureAdapter(seen),
          },
        );

        assert.strictEqual(visitorInvoked, false);
        assert.strictEqual(seen.config.data, "a=1");
      });

      it("should not use a polluted env.FormData in the default transformRequest", function () {
        let fakeConstructed = false;

        function FakeFormData() {
          fakeConstructed = true;
        }
        FakeFormData.prototype.append = function () {};

        pollute("env", { FormData: FakeFormData });

        const result = defaults.transformRequest[0].call(
          {},
          { a: "1" },
          AxiosHeaders.from({ "Content-Type": "multipart/form-data" }),
        );

        assert.strictEqual(fakeConstructed, false);
        assert.ok(!(result instanceof FakeFormData));
      });

      it("should not use a polluted transitional in the default transformResponse", function () {
        pollute("transitional", {
          silentJSONParsing: true,
          forcedJSONParsing: false,
          clarifyTimeoutError: false,
        });

        const result = defaults.transformResponse[0].call({}, '{"a":1}');

        assert.deepStrictEqual(result, { a: 1 });
      });

      it("should not use a polluted responseType in the default transformResponse", function () {
        pollute("responseType", "text");

        const result = defaults.transformResponse[0].call({}, '{"a":1}');

        assert.deepStrictEqual(result, { a: 1 });
      });
    });

    describe("http adapter", function () {
      it("should not route requests through a polluted transport (credential exfiltration)", async function () {
        this.timeout(10000);
        let hijacked;
        const server = await startEchoServer();

        try {
          pollute("transport", {
            request: function (options, cb) {
              hijacked = options;
              return http.request(options, cb);
            },
          });

          const response = await axios.get(serverURL(server, "/secret"), {
            auth: { username: "svc_account", password: "hunter2" },
          });

          assert.strictEqual(hijacked, undefined, "polluted transport intercepted the request");
          assert.strictEqual(response.data.url, "/secret");
          assert.strictEqual(
            response.data.authorization,
            "Basic " + Buffer.from("svc_account:hunter2").toString("base64"),
          );
        } finally {
          delete Object.prototype.transport;
          await stopServer(server);
        }
      });

      it("should not route requests through a polluted transport when the http adapter gets a plain config", async function () {
        this.timeout(10000);
        let hijacked;
        const server = await startEchoServer();

        try {
          pollute("transport", {
            request: function (options, cb) {
              hijacked = options;
              return http.request(options, cb);
            },
          });

          const response = await httpAdapter({
            method: "get",
            url: serverURL(server, "/direct"),
            headers: {},
            proxy: false,
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0,
          });
          const data = JSON.parse(response.data);

          assert.strictEqual(hijacked, undefined, "polluted transport intercepted the request");
          assert.strictEqual(data.url, "/direct");
        } finally {
          delete Object.prototype.transport;
          await stopServer(server);
        }
      });

      it("should still honor an own transport", async function () {
        let captured;

        const response = await axios.get("http://stub.invalid/own", {
          transport: stubTransport('{"ok":true}', function (options) {
            captured = options;
          }),
          maxRedirects: 0,
        });

        assert.ok(captured, "own transport was not invoked");
        assert.deepStrictEqual(response.data, { ok: true });
      });

      it("should not pass a polluted lookup/family to the transport", async function () {
        let captured;
        let lookupInvoked = false;

        pollute("lookup", function (hostname, opt, cb) {
          lookupInvoked = true;
          cb(null, "127.0.0.1", 4);
        });
        pollute("family", 6);

        await axios.get("http://stub.invalid/", {
          transport: stubTransport('{"ok":true}', function (options) {
            captured = options;
          }),
          maxRedirects: 0,
        });

        assert.ok(captured, "transport was not invoked");
        assert.strictEqual(ownValue(captured, "lookup"), undefined);
        assert.strictEqual(ownValue(captured, "family"), undefined);
        assert.strictEqual(lookupInvoked, false);
      });

      it("should not use a polluted responseType to change response decoding", async function () {
        pollute("responseType", "arraybuffer");

        const response = await axios.get("http://stub.invalid/", {
          transport: stubTransport('{"ok":true}'),
          maxRedirects: 0,
        });

        assert.deepStrictEqual(response.data, { ok: true });
      });

      it("should not use a polluted responseEncoding to change response decoding", async function () {
        pollute("responseEncoding", "base64");

        const response = await axios.get("http://stub.invalid/", {
          transport: stubTransport('{"ok":true}'),
          maxRedirects: 0,
        });

        assert.deepStrictEqual(response.data, { ok: true });
      });

      it("should not let a polluted validateStatus accept error responses", async function () {
        pollute("validateStatus", function () {
          return true;
        });

        let error;
        try {
          await axios.get("http://stub.invalid/", {
            transport: stubTransport('{"error":true}', null, 500),
            maxRedirects: 0,
          });
        } catch (err) {
          error = err;
        }

        assert.ok(error, "a 500 response was accepted");
        assert.strictEqual(error.response.status, 500);
      });

      it("should not use a polluted env.Blob for data: URIs", async function () {
        let fakeConstructed = false;

        function FakeBlob() {
          fakeConstructed = true;
        }

        pollute("env", { Blob: FakeBlob });

        let response;
        let error;
        try {
          response = await httpAdapter({
            method: "get",
            url: "data:text/plain;base64,SGVsbG8=",
            headers: {},
            responseType: "blob",
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0,
          });
        } catch (err) {
          // Runtimes without a global Blob reject ("Blob is not supported") once
          // the polluted constructor is ignored; that is an acceptable outcome.
          error = err;
        }

        assert.strictEqual(fakeConstructed, false);
        if (error) {
          assert.ok(/Blob is not supported/.test(error.message), error.message);
        }
        if (response) {
          assert.ok(!(response.data instanceof FakeBlob));
        }
      });
    });
  });
});
