import { test } from "node:test";
import assert from "node:assert/strict";
import { connectCommands, loginMethods, splitAddress } from "../connection.js";

test("addresses split into host and port", () => {
  assert.deepEqual(splitAddress("127.0.0.1:2122"), { host: "127.0.0.1", port: "2122" });
  assert.deepEqual(splitAddress("[::1]:2122"), { host: "::1", port: "2122" });
  assert.deepEqual(splitAddress(":2122"), { host: "", port: "2122" });
});

test("the loopback profile is reached on this machine", () => {
  const server = { sftp_address: "[::1]:2200", profile: "loopback", control_hosts: [], users: [{ name: "test" }], default_login: { user: "test", password: "test" } };
  assert.deepEqual(connectCommands(server), [{ where: "on this machine", command: "sftp -P 2200 test@[::1]" }]);
});

test("the container profile is reached by its service's name", () => {
  const server = { sftp_address: ":2122", profile: "container", control_hosts: ["sftpit"], users: [{ name: "partner-b" }] };
  assert.deepEqual(connectCommands(server), [{ where: "in the compose network", command: "sftp -P 2122 partner-b@sftpit" }]);
  assert.deepEqual(connectCommands({ ...server, control_hosts: [] }), []);
});

test("login methods never say more than how", () => {
  assert.equal(loginMethods({ password: true, keys: 0 }), "password");
  assert.equal(loginMethods({ password: false, keys: 1 }), "1 key");
  assert.equal(loginMethods({ password: true, keys: 2 }), "password or 2 keys");
});
