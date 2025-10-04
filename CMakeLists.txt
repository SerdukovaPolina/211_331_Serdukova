cmake_minimum_required(VERSION 3.19)
project(211_331_Serdukova LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets)

set(OPENSSL_ROOT_DIR "C:/Qt/Tools/OpenSSLv3/Win_x64")
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

qt_add_executable(211_331_Serdukova
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

target_link_libraries(211_331_Serdukova
    PRIVATE
        Qt::Core
        Qt::Widgets
        OpenSSL::SSL
        OpenSSL::Crypto
)

include(GNUInstallDirs)

install(TARGETS 211_331_Serdukova
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET 211_331_Serdukova
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
