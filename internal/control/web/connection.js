// How to connect to the SFTP server, from what the server route reports.

// splitAddress splits a listen address, such as "127.0.0.1:2122",
// "[::1]:2122" or ":2122", into its host and port.
export function splitAddress(address) {
  const i = address.lastIndexOf(":");
  return { host: address.slice(0, i).replace(/^\[(.*)\]$/, "$1"), port: address.slice(i + 1) };
}

// connectCommands returns sftp commands that log in to the server, each
// with where it works: on this machine for the loopback profile, and in
// the compose network by each control host's name for the container
// profile, whose published port on the host sftpit cannot know.
export function connectCommands(server) {
  const user = server.default_login?.user ?? server.users[0]?.name;
  if (user === undefined) {
    return [];
  }
  const { host, port } = splitAddress(server.sftp_address);
  if (server.profile === "container") {
    return server.control_hosts.map((name) => ({ where: "in the compose network", command: command(user, name, port) }));
  }
  return [{ where: "on this machine", command: command(user, host, port) }];
}

function command(user, host, port) {
  const address = host.includes(":") ? `[${host}]` : host;
  return `sftp -P ${port} ${user}@${address}`;
}

// loginMethods says how a user logs in, as the server route describes the
// user, without saying with what.
export function loginMethods(user) {
  const keys = user.keys === 1 ? "1 key" : `${user.keys} keys`;
  if (user.password && user.keys > 0) {
    return `password or ${keys}`;
  }
  return user.password ? "password" : keys;
}
