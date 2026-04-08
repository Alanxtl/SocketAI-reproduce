/**
 * @name Suspicious filesystem access
 * @description Flags file-system APIs often used for tampering, persistence, or harvesting.
 * @kind problem
 * @id socketai/js/suspicious-filesystem
 * @problem.severity warning
 */

import javascript

from CallExpr call, string sinkName
where
  sinkName = call.getCalleeName() and
  sinkName in [
    "appendFile",
    "appendFileSync",
    "copyFile",
    "copyFileSync",
    "createReadStream",
    "createWriteStream",
    "readFile",
    "readFileSync",
    "readdir",
    "readdirSync",
    "rename",
    "renameSync",
    "unlink",
    "unlinkSync",
    "writeFile",
    "writeFileSync"
  ]
select call, "Potential filesystem activity via " + sinkName + "."
