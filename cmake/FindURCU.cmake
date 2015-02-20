# - Find Userspace Read-Copy-Update library
# Find liburcu includes and library.
# Once done this will define
#
#  URCU_INCLUDE_DIRS   - where to find header files, etc.
#  URCU_LIBRARIES      - List of LIBURCU libraries.
#  URCU_FOUND          - True if liburcu is found.
#

FIND_PATH(URCU_ROOT_DIR
	NAMES include/urcu.h
)

SET(URCU_NAME urcu)

FIND_LIBRARY(URCU_LIBRARY
	NAMES ${URCU_NAME}
	HINTS ${URCU_ROOT_DIR}/lib
)

FIND_LIBRARY(URCU_COMMON_LIBRARY
	NAMES "urcu-common"
	HINTS ${URCU_ROOT_DIR}/lib
)

SET(URCU_LIBRARIES ${URCU_LIBRARY} ${URCU_COMMON_LIBRARY})

FIND_PATH(URCU_INCLUDE_DIRS
	NAMES urcu.h
	HINTS ${URCU_ROOT_DIR}/include
)

# handle the QUIETLY and REQUIRED arguments and set URCU_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(liburcu REQUIRED_VARS
	URCU_LIBRARIES
	URCU_INCLUDE_DIRS)

MARK_AS_ADVANCED(
	URCU_ROOT_DIR
	URCU_LIBRARIES
	URCU_INCLUDE_DIRS
)
