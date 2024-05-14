#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "libuv::uv" for configuration "Release"
set_property(TARGET libuv::uv APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libuv::uv PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/uv.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/uv.dll"
  )

list(APPEND _cmake_import_check_targets libuv::uv )
list(APPEND _cmake_import_check_files_for_libuv::uv "${_IMPORT_PREFIX}/lib/uv.lib" "${_IMPORT_PREFIX}/bin/uv.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
