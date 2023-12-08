Off-Line Wi-fi Indirect Analyzer
------------------------------
Application for offline Wi-Fi traffic analysis. Allows you to determine and visualize the topology of wireless 
networks by indirect signs, calculate channel utilization, find out the probability of data exchange between 
the selected station and access point by day of the week.

Warning
-------
For educational purposes only.
The author is not responsible for the actions of the users of this program

Platforms
---------
* Linux

Pre-requirements
----------------
* Tshark
* Mergecap
* Python

Installation
------------
1. Make sure that actual version of Python is installed
2. Clone the repo
3. Cd into cloned directory.
4. Create and activate virtual environment. For example: 
    ~~~
    $ virtualenv venv
    $ source venv/bin/activate
    ~~~
5. Install requirements:
    ~~~
    (venv)$ pip install -r requirements.txt
    ~~~

Running
-------
1. Place files into the current directory
2. Run the app:
    ~~~
    (venv)$ python main.py
    ~~~

Workflow
--------
1. Import files to analyze using interactive menu
2. Choose any available statistics option in the main menu

Collect data to analyze
-----------------------
1. Stop conflicting services
    ~~~
    $ sudo systemctl stop NetworkManager wpa_supplicant.service networking.service
    ~~~
   
2. Set the compatible wi-fi adapter to monitoring mode
    ~~~
    $ ip link set <device> down
    $ ip link set <device> down
    $ iw <device> set monitor control
    $ ip link set <device> up
    ~~~
    Sometimes you also should do: ``rfkill unblock wifi`` before setting the device up
3. Collect frames with tcpdump / airodump-ng / etc.

The preferred way of collecting data is to use ``channel_hopping.sh`` script which is a brief re-write of 
[this article](https://netbeez.net/blog/linux-channel-hopping-wifi-packet-capturing/)
because airodump-ng doesn't save Radio Tap headers and tcpdump by itself doesn't perform channel hopping.
Probably you should re-write script for your hardware if supported channels/channel width are different.

For example:
~~~
$ chmod +x channel_hopping.sh
$ ./channel_hopping.sh  HT20 wlan0

# anoter terminal tab:
$ sudo tcpdump -i <device> -w /path/to/save.pcap
~~~