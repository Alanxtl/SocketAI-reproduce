/**
 * @name Suspicious code or process execution
 * @description Flags common execution sinks often abused by malicious packages.
 * @kind problem
 * @id socketai/js/suspicious-exec
 * @problem.severity warning
 */

import javascript

from CallExpr call, string sinkName
where
  sinkName = call.getCalleeName() and
  sinkName in ["eval", "exec", "execSync", "spawn", "spawnSync", "fork"]
select call, "Potential code or process execution via " + sinkName + "."
