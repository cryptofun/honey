#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/honey.ico

convert ../../src/qt/res/icons/honey-16.png ../../src/qt/res/icons/honey-32.png ../../src/qt/res/icons/honey-48.png ${ICON_DST}
