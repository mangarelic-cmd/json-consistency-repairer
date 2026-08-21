# compact authoritative constraint DSL
scope /rows
require currency default "CAD"
type qty integer
type price number
linear subtotal_rule: subtotal + tax = total
