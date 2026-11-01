const child_process = require("child_process");

function insecure(req, value) {
  eval(value);
  new Function(value);
  const agent = { rejectUnauthorized: false };
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const command = req.query.command;
  child_process.exec(command);
  return agent;
}
