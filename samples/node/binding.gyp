{
  "targets": [
    {
      "target_name": "phxp_native",
      "sources": [
        "native/phxp_native.cc"
      ],
      "cflags_cc": [
        "-std=c++17",
        "-fexceptions",
        "-Wall",
        "-Wextra",
        "-Werror"
      ],
      "cflags_cc!": [
        "-fno-exceptions"
      ],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "CLANG_CXX_LIBRARY": "libc++",
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "GCC_TREAT_WARNINGS_AS_ERRORS": "YES",
        "WARNING_CFLAGS": [
          "-Wall",
          "-Wextra"
        ]
      },
      "defines": [
        "NAPI_VERSION=8"
      ]
    }
  ]
}
