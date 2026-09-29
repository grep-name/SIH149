# CMake generated Testfile for 
# Source directory: /home/og/projects/SIH149
# Build directory: /home/og/projects/SIH149/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(selftest "/home/og/projects/SIH149/build/forge" "selftest")
set_tests_properties(selftest PROPERTIES  _BACKTRACE_TRIPLES "/home/og/projects/SIH149/CMakeLists.txt;89;add_test;/home/og/projects/SIH149/CMakeLists.txt;0;")
add_test(build_image "/home/og/projects/SIH149/build/forge_mkimage" "/home/og/projects/SIH149/build/case.img" "64")
set_tests_properties(build_image PROPERTIES  _BACKTRACE_TRIPLES "/home/og/projects/SIH149/CMakeLists.txt;92;add_test;/home/og/projects/SIH149/CMakeLists.txt;0;")
add_test(clean_audit "/usr/bin/cmake" "-E" "rm" "-f" "/home/og/projects/SIH149/build/test-audit.log")
set_tests_properties(clean_audit PROPERTIES  _BACKTRACE_TRIPLES "/home/og/projects/SIH149/CMakeLists.txt;95;add_test;/home/og/projects/SIH149/CMakeLists.txt;0;")
add_test(recover_image "/home/og/projects/SIH149/build/forge" "recover" "--source" "/home/og/projects/SIH149/build/case.img" "--out" "/home/og/projects/SIH149/build/recovered" "--report" "/home/og/projects/SIH149/build/recovery.json" "--audit-log" "/home/og/projects/SIH149/build/test-audit.log" "--quiet")
set_tests_properties(recover_image PROPERTIES  DEPENDS "build_image;clean_audit" _BACKTRACE_TRIPLES "/home/og/projects/SIH149/CMakeLists.txt;98;add_test;/home/og/projects/SIH149/CMakeLists.txt;0;")
add_test(score_recovery "/home/og/projects/SIH149/build/forge_score" "/home/og/projects/SIH149/build/case.img.manifest.csv" "/home/og/projects/SIH149/build/recovery.json")
set_tests_properties(score_recovery PROPERTIES  DEPENDS "recover_image" _BACKTRACE_TRIPLES "/home/og/projects/SIH149/CMakeLists.txt;104;add_test;/home/og/projects/SIH149/CMakeLists.txt;0;")
add_test(verify_audit "/home/og/projects/SIH149/build/forge" "audit" "verify" "--log" "/home/og/projects/SIH149/build/test-audit.log")
set_tests_properties(verify_audit PROPERTIES  DEPENDS "recover_image" _BACKTRACE_TRIPLES "/home/og/projects/SIH149/CMakeLists.txt;108;add_test;/home/og/projects/SIH149/CMakeLists.txt;0;")
