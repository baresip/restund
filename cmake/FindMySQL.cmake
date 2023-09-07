if(NOT DEFINED MySQL_ROOT)
    find_package(PkgConfig QUIET)
endif()
if(PkgConfig_FOUND AND NOT DEFINED MySQL_ROOT)
    pkg_check_modules(PC_MySQL QUIET "mysqlclient")
    set(MySQL_include_dir_hints ${PC_MySQL_INCLUDEDIR})
    set(MySQL_library_hints ${PC_MySQL_LIBDIR})
    set(MySQL_library_hints_debug "")
else()
    set(MySQL_include_dir_hints "")
    if(NOT DEFINED MySQL_LIBRARY_DIR)
        set(MySQL_LIBRARY_DIR "${MySQL_ROOT}/lib")
    endif()
    set(MySQL_library_hints "${MySQL_LIBRARY_DIR}")
    set(MySQL_library_hints_debug "${MySQL_LIBRARY_DIR}/debug")
endif()

find_path(MySQL_INCLUDE_DIR
          NAMES mysql.h
          HINTS "${MySQL_include_dir_hints}"
          PATH_SUFFIXES mysql mariadb)

find_library(MySQL_LIBRARY
             NO_PACKAGE_ROOT_PATH
             NAMES libmysql mysql mysqlclient libmariadb mariadb
             HINTS ${MySQL_library_hints})

if(MySQL_library_hints_debug)
    find_library(MySQL_LIBRARY_DEBUG
                 NO_PACKAGE_ROOT_PATH
                 NAMES libmysql mysql mysqlclient libmariadb mariadb
                 HINTS ${MySQL_library_hints_debug})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MySQL DEFAULT_MSG MySQL_LIBRARY MySQL_INCLUDE_DIR)

if(MySQL_FOUND)
  set(MySQL_INCLUDE_DIRS "${MySQL_INCLUDE_DIR}")
  set(MySQL_LIBRARIES "${MySQL_LIBRARY}")
  if(NOT TARGET MySQL::MySQL)
    add_library(MySQL::MySQL UNKNOWN IMPORTED)
    set_target_properties(MySQL::MySQL PROPERTIES
                          IMPORTED_LOCATION "${MySQL_LIBRARIES}"
                          INTERFACE_INCLUDE_DIRECTORIES "${MySQL_INCLUDE_DIRS}")
    if(MySQL_LIBRARY_DEBUG)
      set_target_properties(MySQL::MySQL PROPERTIES
                            IMPORTED_LOCATION_DEBUG "${MySQL_LIBRARY_DEBUG}")
    endif()
  endif()
endif()

mark_as_advanced(MySQL_INCLUDE_DIR MySQL_LIBRARY)
