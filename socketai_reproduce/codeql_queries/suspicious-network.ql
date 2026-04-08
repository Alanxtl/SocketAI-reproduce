/**
 * @name Suspicious network activity
 * @description Flags network APIs commonly used to exfiltrate data or fetch payloads.
 * @kind problem
 * @id socketai/js/suspicious-network
 * @problem.severity warning
 */

import javascript

from CallExpr call, string sinkName
where
  sinkName = call.getCalleeName() and
  sinkName in [
    "connect",
    "createConnection",
    "fetch",
    "lookup",
    "request",
    "resolve",
    "sendBeacon"
  ]
select call, "Potential network activity via " + sinkName + "."
