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

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
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
});
