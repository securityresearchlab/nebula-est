-- ./package.dhall
let types = ./types.dhall

let schemas = ./schemas.dhall

let utils = ./utils.dhall

in  types // schemas // utils
