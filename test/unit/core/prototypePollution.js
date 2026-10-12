"use strict";

import assert from "assert";
import fs from "fs";
import http from "http";
import stream from "stream";
import EventEmitter from "events";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import AxiosError from "../../../lib/core/AxiosError.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import resolveConfig from "../../../lib/helpers/resolveConfig.js";
import httpAdapter from "../../../lib/adapters/http.js";
import defaults from "../../../lib/defaults/index.js";

const nodeMajorVersion = parseInt(process.versions.node.split(".")[0], 10);

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.adapter;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.proxy;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.transitional;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.responseType;
    delete Object.prototype.fetchOptions;
    delete Object.prototype.username;
    delete Object.prototype.password;
    delete Object.prototype.hostname;
    delete Object.prototype.host;
    delete Object.prototype.port;
    delete Object.prototype.protocol;
    delete Object.prototype.get;
    delete Object.prototype.set;
    delete Object.prototype.headers;
    delete Object.prototype.customNested;
    delete Object.prototype.common;
    delete Object.prototype.options;
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

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and resolveConfig, bypassing hasOwnProperty and
  // allowing prototype pollution gadgets (auth, baseURL, socketPath,
  // beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.auth', async function () {
      this.timeout(10000);
      // setProxy reads `proxy.auth` directly. When `proxy` is a
      // URL instance from the environment proxy or a plain object without an own `auth`,
      // a polluted Object.prototype.auth would otherwise be base64-encoded into the
      // Proxy-Authorization header, leaking attacker-controlled credentials.
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.auth must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.username', async function () {
      this.timeout(10000);
      // The setProxy username/password branch builds basic creds from `proxy.username`
      // and `proxy.password`. For a plain object proxy, both reads must be guarded
      // against prototype pollution.
      Object.prototype.username = 'attacker';
      Object.prototype.password = 'exfil';

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.username must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj resolveConfig baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });
  });

  // Backport coverage for this release line: the http adapter already read
  // auth/baseURL pollution-safely, but resolveConfig (used by the xhr and fetch
  // adapters), Axios#getUri and the http adapter's beforeRedirects map still
  // inherited from Object.prototype (GHSA-q8qp-cvcw-x6jj).
  describe('GHSA-q8qp-cvcw-x6jj resolveConfig / getUri / beforeRedirects gadgets', function () {
    function listen(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function close(server) {
      return new Promise((resolve) => {
        if (typeof server.closeAllConnections === 'function') {
          server.closeAllConnections();
        }
        server.close(resolve);
      });
    }

    it('should not prepend Object.prototype.baseURL in resolveConfig', function () {
      Object.prototype.baseURL = 'http://evil.example.com';
      const resolved = resolveConfig({ url: '/api' });
      assert.strictEqual(resolved.url, '/api');
    });

    it('should not add an Authorization header from Object.prototype.auth in resolveConfig', function () {
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };
      const resolved = resolveConfig({ url: '/api' });
      assert.strictEqual(resolved.headers.get('Authorization'), undefined);
    });

    it('should still honor own baseURL and auth in resolveConfig', function () {
      if (typeof btoa !== 'function') this.skip();
      const resolved = resolveConfig({
        url: '/api',
        baseURL: 'http://example.com',
        auth: { username: 'user', password: 'pass' }
      });
      assert.strictEqual(resolved.url, 'http://example.com/api');
      assert.strictEqual(
        resolved.headers.get('Authorization'),
        'Basic ' + Buffer.from('user:pass').toString('base64')
      );
    });

    it('should not prepend Object.prototype.baseURL in axios.getUri', function () {
      Object.prototype.baseURL = 'http://evil.example.com';
      assert.strictEqual(axios.getUri({ url: '/api' }), '/api');
    });

    it('should not hijack fetch adapter requests via Object.prototype.baseURL', async function () {
      if (typeof fetch !== 'function') this.skip();
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = await listen((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api', { adapter: 'fetch' });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await close(hijacker);
      }
    });

    it('should not invoke Object.prototype.config through beforeRedirects during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.defineProperty(Object.prototype, 'config', {
        value: function polluted() {
          hijackCalled = true;
        },
        configurable: true,
        writable: true
      });

      const target = await listen((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      const { port: targetPort } = target.address();

      const redirector = await listen((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        delete Object.prototype.config;
        await close(redirector);
        await close(target);
      }
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe('utils.merge prototype-chain read', function () {
    it('should not pick up polluted Object.prototype.<key> as the existing value', function () {
      Object.prototype.headers = { evil: 'yes' };

      const result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      assert.strictEqual(result.headers.evil, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
    });

    it('should not absorb polluted nested objects when the key is absent from inputs', function () {
      // When the source does not carry `customNested`, the merged result should
      // not surface it either, even if Object.prototype carries it.
      Object.prototype.customNested = { evil: 'yes' };

      const result = utils.merge({}, { safe: 'value' });

      assert.strictEqual(result.hasOwnProperty('customNested'), false);
      assert.strictEqual(result.safe, 'value');
    });

    it('should not copy polluted inherited header buckets into nested headers', function () {
      let result;

      Object.prototype.common = { 'x-polluted-common': 'yes' };
      Object.prototype.get = { 'x-polluted-get': 'yes' };

      try {
        result = utils.merge({}, {
          headers: {
            common: {
              Accept: 'application/json',
            },
            get: {
              'x-own-get': 'yes',
            },
          },
        });
      } finally {
        delete Object.prototype.common;
        delete Object.prototype.get;
      }

      assert.strictEqual(result.headers.common.Accept, 'application/json');
      assert.strictEqual(result.headers.get['x-own-get'], 'yes');
      assert.strictEqual(result.headers.common['x-polluted-common'], undefined);
      assert.strictEqual(result.headers.get['x-polluted-get'], undefined);
    });

    it('should not merge polluted Object.prototype.auth into a configured proxy auth object', function () {
      Object.prototype.auth = { password: 'polluted-pass' };

      const result = mergeConfig({}, {
        proxy: {
          host: 'localhost',
          port: 4000,
          auth: { username: 'user' },
        },
      });

      assert.strictEqual(result.proxy.auth.username, 'user');
      assert.strictEqual(Object.prototype.hasOwnProperty.call(result.proxy.auth, 'password'), false);
    });
  });

  // Object.defineProperty calls a HasProperty check on `get`/`set` of the
  // descriptor. A polluted Object.prototype.get with a non-function value would
  // throw TypeError at every defineProperty site that uses a plain literal
  // descriptor. Each fixed site should be shielded with `__proto__: null`.
  describe('Object.defineProperty descriptor literals', function () {
    // Re-evaluate a lib module's top-level code under the current (polluted)
    // prototype without going through the ESM loader, so module-load-time
    // descriptor literals are exercised. Import lines are stripped, the named
    // bindings are injected and `export default` becomes the return value.
    function evaluateModuleBody(relativePath, bindings) {
      const source = fs.readFileSync(new URL(relativePath, import.meta.url), 'utf8')
        .replace(/^import\s.*$/gm, '')
        .replace(/^export default\s/m, 'return ');
      const names = Object.keys(bindings);
      return new Function(...names, source)(...names.map((name) => bindings[name]));
    }

    it('should construct AxiosError when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      try {
        const err = new AxiosError('hello', 'ECODE');

        assert.strictEqual(err.message, 'hello');
        assert.strictEqual(err.code, 'ECODE');
      } finally {
        delete Object.prototype.get;
      }
    });

    it('should construct AxiosHeaders accessor methods when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      try {
        // AxiosHeaders.accessor uses Object.defineProperty on the prototype.
        // Triggering a fresh accessor definition exercises the descriptor literal.
        AxiosHeaders.accessor('X-Pp-Test');
      } finally {
        delete Object.prototype.get;
      }

      const h = new AxiosHeaders();
      h.setXPpTest('value');
      assert.strictEqual(h.getXPpTest(), 'value');
    });

    it('should not throw in mergeConfig when Object.prototype.get is polluted', function () {
      let result;
      Object.prototype.get = 'attacker';

      try {
        result = mergeConfig({}, { url: '/x', method: 'get' });
      } finally {
        delete Object.prototype.get;
      }

      assert.strictEqual(result.url, '/x');
      assert.strictEqual(result.method, 'get');
      assert.strictEqual(typeof result.hasOwnProperty, 'function');
    });

    it('should not throw in utils.extend when Object.prototype.get is polluted', function () {
      const a = {};
      const b = { x: 1, fn() {} };
      Object.prototype.get = 'attacker';

      try {
        utils.extend(a, b);
      } finally {
        delete Object.prototype.get;
      }

      assert.strictEqual(a.x, 1);
      assert.strictEqual(typeof a.fn, 'function');
    });

    it('should not throw in utils.extend with thisArg when Object.prototype.get is polluted', function () {
      const a = {};
      const ctx = { tag: 'ctx' };
      const b = {
        method() {
          return this.tag;
        },
      };
      Object.prototype.get = 'attacker';

      try {
        utils.extend(a, b, ctx);
      } finally {
        delete Object.prototype.get;
      }

      assert.strictEqual(a.method(), 'ctx');
    });

    it('should not throw in utils.inherits when Object.prototype.get is polluted', function () {
      function Parent() {}
      function Child() {}
      Object.prototype.get = 'attacker';

      try {
        utils.inherits(Child, Parent);
      } finally {
        delete Object.prototype.get;
      }

      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it('should also be shielded against a polluted Object.prototype.set', function () {
      let err;
      let result;
      Object.prototype.set = 'attacker';

      // Same surface as `get` — ToPropertyDescriptor checks both.
      try {
        err = new AxiosError('hello');
        result = mergeConfig({}, { url: '/x' });
      } finally {
        delete Object.prototype.set;
      }

      assert.strictEqual(err.message, 'hello');
      assert.strictEqual(result.url, '/x');
    });

    it('should not throw in mergeConfig when Object.prototype get and set are polluted functions', function () {
      Object.prototype.get = function () {};
      Object.prototype.set = function () {};

      try {
        assert.doesNotThrow(function () {
          mergeConfig({}, {
            url: '/users',
            headers: {
              common: {
                Accept: 'application/json',
              },
            },
          });
        });
      } finally {
        delete Object.prototype.get;
        delete Object.prototype.set;
      }
    });

    it('should prepare request headers without descriptor errors when get and set are polluted', async function () {
      let capturedAccept;

      Object.prototype.get = function () {};
      Object.prototype.set = function () {};

      try {
        const instance = axios.create({
          adapter: function adapter(config) {
            capturedAccept = config.headers.Accept;
            return Promise.resolve({
              data: null,
              status: 200,
              statusText: 'OK',
              headers: {},
              config: config,
              request: {},
            });
          },
          headers: {
            common: {
              Accept: 'application/json',
            },
          },
        });

        await instance.get('/users');
      } finally {
        delete Object.prototype.get;
        delete Object.prototype.set;
      }

      assert.strictEqual(capturedAccept, 'application/json');
    });

    it('should define AxiosError code descriptors when Object.prototype.get is polluted at load time', function () {
      let FreshAxiosError;
      Object.prototype.get = 'attacker';

      try {
        FreshAxiosError = evaluateModuleBody('../../../lib/core/AxiosError.js', { utils });
      } finally {
        delete Object.prototype.get;
      }

      assert.strictEqual(FreshAxiosError.ERR_BAD_REQUEST, 'ERR_BAD_REQUEST');
      assert.strictEqual(FreshAxiosError.prototype.isAxiosError, true);
    });

    it('should name the known adapters when Object.prototype.get is polluted at load time', function () {
      let fresh;
      function httpStub() {}
      function xhrStub() {}
      Object.prototype.get = 'attacker';

      try {
        fresh = evaluateModuleBody('../../../lib/adapters/adapters.js', {
          utils,
          httpAdapter: httpStub,
          xhrAdapter: xhrStub,
          fetchAdapter: false,
          AxiosError,
        });
      } finally {
        delete Object.prototype.get;
      }

      assert.strictEqual(fresh.adapters.http, httpStub);
      assert.strictEqual(httpStub.adapterName, 'http');
      assert.strictEqual(xhrStub.adapterName, 'xhr');
    });
  });

  // The per-method / common header buckets are flattened in Axios#_request.
  // A bucket that is not an own property (e.g. `options`, which has no default
  // bucket) must not be inherited from a polluted Object.prototype.
  describe('header bucket gadgets', function () {
    function captureAdapter(capture) {
      return function adapter(config) {
        capture(config.headers);
        return Promise.resolve({
          data: null,
          status: 200,
          statusText: 'OK',
          headers: {},
          config: config,
          request: {},
        });
      };
    }

    it('should not merge a polluted Object.prototype.<method> header bucket', async function () {
      let captured;
      Object.prototype.options = { 'X-Polluted-Options': 'yes' };

      try {
        await axios.options('/x', {
          adapter: captureAdapter((headers) => {
            captured = headers;
          }),
        });
      } finally {
        delete Object.prototype.options;
      }

      assert.ok(captured, 'adapter was not invoked');
      assert.strictEqual(captured.has('X-Polluted-Options'), false);
    });

    it('should not merge a polluted Object.prototype.common header bucket', async function () {
      let captured;
      const instance = new axios.Axios({});
      Object.prototype.common = { 'X-Polluted-Common': 'yes' };

      try {
        await instance.request({
          url: '/x',
          headers: { 'X-Request': 'request' },
          adapter: captureAdapter((headers) => {
            captured = headers;
          }),
        });
      } finally {
        delete Object.prototype.common;
      }

      assert.ok(captured, 'adapter was not invoked');
      assert.strictEqual(captured.get('X-Request'), 'request');
      assert.strictEqual(captured.has('X-Polluted-Common'), false);
    });
  });

  // End-to-end regressions covering published advisory PoCs against full axios
  // request flow. Each test mirrors the exploit scenario from the advisory and
  // asserts the attack does not succeed.
  describe('advisory regression — full request flow', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    // Full MITM via prototype pollution gadget in
    // `config.proxy`. mergeConfig must not surface a polluted Object.prototype.proxy
    // as the merged config's proxy, otherwise every request would route through
    // an attacker-controlled host.
    it('polluted Object.prototype.proxy must not redirect requests through an attacker proxy', async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startServer((req, res) => {
        proxyHits.push({
          url: req.url,
          authorization: req.headers.authorization,
          host: req.headers.host,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });

      const realHits = [];
      const realServer = await startServer((req, res) => {
        realHits.push({ url: req.url });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":"real"}');
      });

      try {
        Object.prototype.proxy = {
          protocol: 'http',
          host: '127.0.0.1',
          port: attackerProxy.address().port,
        };

        const realPort = realServer.address().port;
        const res = await axios.get(`http://127.0.0.1:${realPort}/api/secrets`, {
          auth: { username: 'admin', password: 'SuperSecret123!' },
        });

        assert.strictEqual(proxyHits.length, 0, 'attacker proxy must not receive any request');
        assert.strictEqual(realHits.length, 1, 'request must reach the real target');
        assert.deepStrictEqual(res.data, { data: 'real' });
      } finally {
        delete Object.prototype.proxy;
        await stop(attackerProxy);
        await stop(realServer);
      }
    });

    // Credential theft and response hijacking via
    // prototype pollution gadget in config merge. A polluted
    // Object.prototype.transformResponse function would otherwise execute with
    // `this = config`, exposing `auth.username`/`auth.password` to the attacker.
    it('polluted Object.prototype.transformResponse must not be invoked or leak request credentials', async function () {
      this.timeout(10000);
      let invoked = false;
      let stolen = null;
      Object.prototype.transformResponse = function pollutedTransform(data) {
        invoked = true;
        stolen = {
          url: this && this.url,
          username: this && this.auth && this.auth.username,
          password: this && this.auth && this.auth.password,
          data,
        };
        return true;
      };

      const server = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"secret":"keep-me"}');
      });

      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/users`, {
          auth: { username: 'svc-account', password: 'prod-secret-key-123!' },
        });

        assert.strictEqual(invoked, false, 'polluted transformResponse must not run');
        assert.strictEqual(stolen, null, 'no request context must be captured');
        assert.deepStrictEqual(
          res.data,
          { secret: 'keep-me' },
          'response data must reach the caller untampered'
        );
      } finally {
        delete Object.prototype.transformResponse;
        await stop(server);
      }
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
