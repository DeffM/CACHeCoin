#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/CACHEProject.ico

convert ../../src/qt/res/icons/CACHEProject_16.png ../../src/qt/res/icons/CACHEProject_32.png ../../src/qt/res/icons/CACHEProject_48.png ${ICON_DST}
