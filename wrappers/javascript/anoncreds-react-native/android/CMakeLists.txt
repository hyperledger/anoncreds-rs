project(anoncredsreactnative)
cmake_minimum_required(VERSION 3.4.1)

set (PACKAGE_NAME "anoncredsreactnative")
set (LIB_NAME "anoncreds")
file (GLOB LIBANONCREDS_DIR "${CMAKE_SOURCE_DIR}/../native/mobile/android/${ANDROID_ABI}")

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 14)

if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
  include("${NODE_MODULES_DIR}/react-native/ReactAndroid/cmake-utils/folly-flags.cmake")
  add_compile_options(${folly_FLAGS})
else()
  set (CMAKE_CXX_FLAGS "-DFOLLY_NO_CONFIG=1 -DFOLLY_HAVE_CLOCK_GETTIME=1 -DFOLLY_HAVE_MEMRCHR=1 -DFOLLY_USE_LIBCPP=1 -DFOLLY_MOBILE=1 -DON_ANDROID -DONANDROID -DFOR_HERMES=${FOR_HERMES}")
endif()

set (BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
  find_package(fbjni REQUIRED CONFIG)
  find_package(ReactAndroid REQUIRED CONFIG)
else()
  set (RN_SO_DIR ${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni/first-party/react/jni)
endif()

if(${REACT_NATIVE_VERSION} LESS 66)
  set (INCLUDE_JSI_CPP "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/jsi/jsi.cpp")
  set (INCLUDE_JSIDYNAMIC_CPP "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/jsi/JSIDynamic.cpp")
endif()

include_directories(
  ../cpp
  ../cpp/include
  "${LIBANONCREDS_DIR}"
)

add_library(
  ${PACKAGE_NAME}
  SHARED
  cpp-adapter.cpp
  ../cpp/HostObject.cpp
  ../cpp/turboModuleUtility.cpp
  ../cpp/anoncreds.cpp
)

if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
  target_include_directories(
    ${PACKAGE_NAME}
    PRIVATE
    "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni/react/turbomodule"
    "${NODE_MODULES_DIR}/react-native/ReactCommon"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/react/renderer/graphics/platform/cxx"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/runtimeexecutor"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/yoga"
  )
else()
  file (GLOB LIBFBJNI_INCLUDE_DIR "${BUILD_DIR}/fbjni-*-headers.jar/")

  target_include_directories(
    ${PACKAGE_NAME}
    PRIVATE
    "${LIBFBJNI_INCLUDE_DIR}"
    "${NODE_MODULES_DIR}/react-native/React"
    "${NODE_MODULES_DIR}/react-native/React/Base"
    "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni"
    "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/java/com/facebook/react/turbomodule/core/jni"
    "${NODE_MODULES_DIR}/react-native/ReactCommon"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
    "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
    "${NODE_MODULES_DIR}/hermes-engine/android/include/"
    ${INCLUDE_JSI_CPP} # only on older RN versions
    ${INCLUDE_JSIDYNAMIC_CPP} # only on older RN versions
  )
endif()

file (GLOB LIBRN_DIR "${BUILD_DIR}/react-native-0*/jni/${ANDROID_ABI}")

if(${FOR_HERMES})
  string(APPEND CMAKE_CXX_FLAGS " -DFOR_HERMES=1")

  if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
      find_package(hermes-engine REQUIRED CONFIG)
  elseif(${REACT_NATIVE_VERSION} GREATER_EQUAL 69)
    # Bundled Hermes from module `com.facebook.react:hermes-engine` or project `:ReactAndroid:hermes-engine`
    target_include_directories(
      ${PACKAGE_NAME}
      PRIVATE
      "${JS_RUNTIME_DIR}/API"
      "${JS_RUNTIME_DIR}/public"
    )
  else()
    # From `hermes-engine` npm package
    target_include_directories(
      ${PACKAGE_NAME}
      PRIVATE
      "${JS_RUNTIME_DIR}/android/include"
    )
  endif()

  if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
    target_link_libraries(
      ${PACKAGE_NAME}
      "hermes-engine::libhermes"
    )
  else()
    target_link_libraries(
      ${PACKAGE_NAME}
      "${BUILD_DIR}/third-party-ndk/hermes/jni/${ANDROID_ABI}/libhermes.so"
    )
  endif()
else()
  file (GLOB LIBJSC_DIR "${BUILD_DIR}/android-jsc*.aar/jni/${ANDROID_ABI}")

  if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
          set(JS_ENGINE_LIB ReactAndroid::jscexecutor)
  else()
    # Use JSC
    find_library(
      JS_ENGINE_LIB
      jscexecutor
      PATHS ${LIBRN_DIR}
      NO_CMAKE_FIND_ROOT_PATH
    )
  endif()
  target_link_libraries(
    ${PACKAGE_NAME}
    ${JS_ENGINE_LIB}
  )
endif()

if(${REACT_NATIVE_VERSION} LESS 71)
  find_library(
    FBJNI_LIB
    fbjni
    PATHS ${LIBRN_DIR}
    NO_CMAKE_FIND_ROOT_PATH
  )
endif()

if(${REACT_NATIVE_VERSION} LESS 71)
  find_library(
    REACT_NATIVE_JNI_LIB
    reactnativejni
    PATHS ${LIBRN_DIR}
    NO_CMAKE_FIND_ROOT_PATH
  )
endif()

if(${REACT_NATIVE_VERSION} GREATER_EQUAL 71)
  target_link_libraries(
    ${PACKAGE_NAME}
    ReactAndroid::jsi
    ReactAndroid::reactnativejni
    fbjni::fbjni
  )
elseif(${REACT_NATIVE_VERSION} LESS 66)
  # JSI lib didn't exist on RN 0.65 and before. Simply omit it.
  set (JSI_LIB "")
else()
  # RN 0.66 distributes libjsi.so, can be used instead of compiling jsi.cpp manually.
  find_library(
    JSI_LIB
    jsi
    PATHS ${LIBRN_DIR}
    NO_CMAKE_FIND_ROOT_PATH
  )
endif()

find_library(
  REANIMATED_LIB
  reanimated
  PATHS ${LIBREANIMATED_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

find_library(
  LOG_LIB
  log
)

find_library(
  ANONCREDS_LIB 
  anoncreds
  paths ${LIBANONCREDS_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

if (NOT ANONCREDS_LIB)
  message(FATAL_ERROR "Could not find ANONCREDS_LIB at: ${LIBANONCREDS_DIR}")
endif()

target_link_libraries(
        ${PACKAGE_NAME}
        ${ANONCREDS_LIB}
        ${LOG_LIB}
        ${JSI_LIB}
        ${REACT_NATIVE_JNI_LIB}
        ${FBJNI_LIB}
        android
)
