const child_process = require("child_process");

function safer(req) {
  const command = "echo ready";
  child_process.exec(command);
  const agent = { rejectUnauthorized: true };
  return agent;
}
