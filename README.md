# Graphml-To-Mininet (EN)

This program converts the .graphml format topology to Mininet executable python topology scripts, mainly referd to:

https://github.com/uniba-ktr/assessing-mininet/blob/master/parser/GraphML-Topo-to-Mininet-Network-Generator.py

Reference code for this project is at the above URL. In this project, all of the code annotation from the original author is reserved.

## Usage

### Basic

#### (1) Download the dataset

Use topology zoo dataset: http://www.topology-zoo.org/dataset.html

Check: Download current dataset as a zip archive

#### (2) Use the alternate dataset in this repository

git clone https://github.com/yyd19981117/Graphml-To-Mininet.git

sudo ./install.sh

To unzip and obtain the topology in .graphml format in "/mini-topologies" path.

Here shows two ways to use this program.

#### Single Operation

python GraphML-to-Mininet.py -argument value

#### Multiple Operations

./gen_topo.sh

This will convert all .graphml files at path "/mini-topologies" into runnable Mininet scripts. They will be put in the "/mini-topologies-done" folder under the current directory.
The generated topologies by this shell script will support RSTP by default. To generate STP-disabled topologies, you can modify and Remove the "--stp" option in  the script "gen_topo.sh".

#### Arguments (Only for single operation)

-f, --file: Input file name including ".graphml". This argument is required.

-o, --output: Output file name, if not exist, the output file will be named as "{$Input_File_Name}" + "-Mininet-Topo.py"

-b, --bw, --bandwidth: Use this to set the bandwidth if some of the link bandwidth data is missing in .graphml, default 128Mbps.

-c, --controller: Remote SDN controller IP address, default 127.0.0.1.

-p, --port: The port number for controller to communicate with Mininet, default 6633.

-s, --stp: Enable Spanning Tree Protocol (STP) to OpenvSwitch for loops. When running topologire, the STP enabled scripts will inform that the controller needs extra time to generate spanning trees. No following arguments is required for this option.

--cli: Enable to set CLI(net) in Mininet scripts, avoiding direct exiting after simulation ends.

### Next Step (The program will prompt when topology conversion is completed)

In the converted Mininet topology, a "USER SIMULATION CODE HERE" area with "#" annotation will be generated

In this area, users can customize and add simulation code to make Mininet simulation automatically

## Performance Improvements

This code can convert and generate all 261 topologies in topology zoo dataset correctly, while the referd program (In the above link) has some bugs, and it is tested to only generate 198/261 topologies successfully.

## Main Improvements

1. Repair the error names of the nodes, includiing redundant names, non-exist names and "None" names. If there is such a situation, then use standard node names instead (s1，s2，s3......).

2. Repair a few situations when node names do not meet the python naming rules or has the same name as a python keyword, then use standard node names instead.

3. Repair the problem of latitude and longitude data missing. The missing latitude and longitude will be set as the average of all the other node latitude and longitude data in the same topology. If all of the latitude and longitude is missing, then the link delay ranges from 0ms to 5ms randomly.

4. Support the bandwidth setting from original topology data. If a link bandwidth ranges in an interval, then the bandwidth is the average of the mininum and the maxinum of the interval.

5. Improved the code style to be consistant with the Mininet - Miniedit - export L2 scripts option.

