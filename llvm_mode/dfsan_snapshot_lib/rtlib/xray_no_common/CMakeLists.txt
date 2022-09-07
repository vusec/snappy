set(XRAY_NO_COMMON_LIB_NAME xray_no_common.a)

if(NOT TARGET xray_no_common_lib)
  add_custom_command(
    OUTPUT ${XRAY_NO_COMMON_LIB_NAME}
    COMMAND ar x ${LIBCLANG_PREFIX}/lib/linux/libclang_rt.xray-x86_64.a
    COMMAND rm sanitizer_*.o
    COMMAND ar cr ${XRAY_NO_COMMON_LIB_NAME} xray_*.o
    DEPENDS ${LIBCLANG_PREFIX}/lib/linux/libclang_rt.xray-x86_64.a
    BYPRODUCTS xray_*.o)

  add_custom_target(xray_no_common_lib ALL DEPENDS ${XRAY_NO_COMMON_LIB_NAME})

  set(XRAY_NO_COMMON_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/${XRAY_NO_COMMON_LIB_NAME}"
      CACHE INTERNAL "")

  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${XRAY_NO_COMMON_LIB_NAME}
          DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

set(XRAY_NO_COMMON_INSTALL_PATH
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${XRAY_NO_COMMON_LIB_NAME}"
    PARENT_SCOPE)
