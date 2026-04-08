/**
 * @name Suspicious download shell command
 * @description Flags string literals that reference common download-oriented shell utilities.
 * @kind problem
 * @id socketai/js/suspicious-download-command
 * @problem.severity warning
 */

import javascript

from StringLiteral literal
where
  literal.getValue().regexpMatch("(?i).*(curl|wget|Invoke-WebRequest|certutil|bitsadmin).*")
select literal, "String literal references a download-capable shell utility."
