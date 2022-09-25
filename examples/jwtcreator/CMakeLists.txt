set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

add_executable(jwtcreator
    dialog.h dialog.cpp
    dialog.ui
    main.cpp
)

target_link_libraries(jwtcreator PRIVATE Qt${QT_VERSION_MAJOR}::Widgets QJsonWebToken)

set_target_properties(jwtcreator PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
)
