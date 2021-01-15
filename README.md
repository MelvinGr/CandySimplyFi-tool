# CandySimplyFi-tool
Tool for getting data of your Candy Simply-Fi devices, works on both windows and linux

I'm using it on my HomeAssistant instance

More info here: https://community.home-assistant.io/t/dishwasher-candy-simply-fi-cdi-6015-wifi/136543

Binaries for windows & linux x64 are in the bin folder

## Compile on Windows
Just use Visual Studio

## Compile on Linux
`g++ CandySimplyFi.cpp -o simplyfi`

## Compile on MacOS
`g++ -std=c++11 CandySimplyFi.cpp -o simplyfi`

## Usage

Usage to retreive key: `./simplyfi <ip> getkey`
  
Usage to get data    : `./simplyfi <ip> <key> <method: config, getStatistics, read>`
