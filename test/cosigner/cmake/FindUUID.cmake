# FindUUID.cmake
if(APPLE)
  # On macOS, uuid is part of the system and doesn't need an external library
  find_path(UUID_INCLUDE_DIR uuid/uuid.h /usr/include)
  
  if(UUID_INCLUDE_DIR)
    set(UUID_FOUND TRUE)
    set(UUID_LIBRARY "") # No library needed on macOS
  else()
    set(UUID_FOUND FALSE)
  endif()
else()
  # For Linux or other UNIX-like systems
  find_path(UUID_INCLUDE_DIR uuid/uuid.h)
  find_library(UUID_LIBRARY NAMES uuid)
endif()

message(STATUS "UUID_LIBRARY=${UUID_LIBRARY}")
message(STATUS "UUID_INCLUDE_DIR=${UUID_INCLUDE_DIR}")

include(FindPackageHandleStandardArgs)
if(APPLE)
  # On macOS, only check for the header file, not the library
  find_package_handle_standard_args(UUID DEFAULT_MSG UUID_INCLUDE_DIR)
else()
  # On Linux, check for both the header and the library
  find_package_handle_standard_args(UUID DEFAULT_MSG UUID_LIBRARY UUID_INCLUDE_DIR)
endif()

if(UUID_FOUND AND NOT TARGET UUID::UUID)
  add_library(UUID::UUID UNKNOWN IMPORTED)
  set_target_properties(UUID::UUID PROPERTIES
    IMPORTED_LOCATION "${UUID_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${UUID_INCLUDE_DIR}")
endif()
