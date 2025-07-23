# Set console color when CMake building project
string(ASCII 27 Esc)
set(Reset "${Esc}[m")
set(Red "${Esc}[31m")
set(Green "${Esc}[32m")
set(Yellow "${Esc}[33m")
set(Blue "${Esc}[34m")

function(print_options COMPILER BUILD)
    message("-- ┌─ Hex Editor Options ────────────────")
    message("-- │ ${Red}Compiler${Reset}  : ${Green}${COMPILER}${Reset}")
    message("-- │ ${Yellow}Build Type${Reset}: ${Blue}${BUILD}${Reset}")
    message("-- └─────────────────────────────────────")
endfunction()
