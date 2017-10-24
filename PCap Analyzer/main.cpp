#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include <iomanip>

#include <pcap.h>
#include "time.h"
//#include <winsock2.h>

#include <list>
#include <map>
#include <vector>

#define SSTR( x ) static_cast< std::ostringstream & >( \
        ( std::ostringstream() << std::dec << x ) ).str()

//#include <CImg.h>
using namespace std;
//using namespace cimg_library;

struct tm timetracker;  // Stores the current time value every ~30 minutes
struct tm currentTime;  // Stores the time of the current packet
struct tm lastTime;     // Stores the time of the last packet
u_int packetCount = 0;
vector<char*> protocolList{ "tcp and ip", "udp" , "icmp"};
int currentProtocol = 0;
int traceCounter = 0;

void printFlowMap();

/* 4 bytes IP address */
class ip_address{
    public:
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;

};
bool operator==(const ip_address p1, const ip_address p2){
    return ((p1.byte1 == p2.byte1)
         && (p1.byte2 == p2.byte2)
         && (p1.byte3 == p2.byte3)
         && (p1.byte4 == p2.byte4));
}
bool operator<(const ip_address p1, const ip_address p2){
    if (p1.byte1 < p2.byte1)
        return true;
    else if (p1.byte1 > p2.byte2)
        return false;
    if (p1.byte2 < p2.byte2)
        return true;
    else if (p1.byte2 > p2.byte2)
        return false;
    if (p1.byte3 < p2.byte3)
        return true;
    else if (p1.byte3 > p2.byte3)
        return false;
    if (p1.byte4 < p2.byte4)
        return true;
    return false;
}

class ip_header{
    public:
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
};
class udp_header{
    public:
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
};


class flowIdentifier{
    // 5-tuple which identifies a flow
public:
    ip_address srcip;
    ip_address dstip;
    u_short srcport;
    u_short dstport;
    u_char proto; // 0 = tcp/ip, 1 = udp, 2 = icmp
};
bool operator==(const flowIdentifier &id1, const flowIdentifier &id2){
    return ( id1.srcip == id2.srcip && id1.dstip == id2.dstip && id1.srcport == id2.srcport && id1.dstport == id2.dstport && id1.proto == id2.proto );
}
class flow{
    // A single packet flow consisting of it's identifier and the packets contained in it
public:
    flowIdentifier identifier;

    vector< pair<tm,long> > packets;
};
class victim{
public:
    ip_address victimIP;
    struct tm attackstart;
    struct tm attackend;
    int rate;
    vector<flow> victimFlows;
};
class trace{
public:
    int numberofPackets = 0;
    struct tm starttime, endtime;
    map<unsigned long long, vector<flow> >flowMap;
    vector<victim> victimVector;
};

vector<trace> traceVector(1);


unsigned long long myHash(const flowIdentifier identifier){
    // Hash function used to search through the stored flow database
    return ( ( ((unsigned long long)(identifier.srcip.byte1) << 24) + ((unsigned long long)(identifier.srcip.byte2) << 16) + ((unsigned long long)(identifier.srcip.byte3) << 8) + (unsigned long long)(identifier.srcip.byte4))* 59)
            ^ (((unsigned long long)(identifier.dstip.byte1) << 24) + ((unsigned long long)(identifier.dstip.byte2) << 16) + ((unsigned long long)(identifier.dstip.byte3) << 8) + (unsigned long long)(identifier.dstip.byte4))
            ^ (identifier.srcport << 16) ^ (identifier.dstport) ^ (identifier.proto);
}


void cleanFlowMap(){
    /* Deletes all flows meeting the following conditions every 30 minutes:
        -- the flow contains less than 100 packets
        -- the last packet was added to the flow more than 5 minutes ago
    */

    char timestr1[32], timestr2[32];
    strftime( timestr1, sizeof timestr1, "%x, %H:%M:%S", &timetracker);
    strftime( timestr2, sizeof timestr2, "%x, %H:%M:%S", &currentTime);
    timetracker = currentTime;


    cout << "Cleaning trace " << traceCounter + 1 << " having seen timestamps\n     " << timestr1 << " (previous) and\n     " << timestr2 << " (current)...\n     Flow count in trace " << traceCounter + 1 << " before: " << traceVector[traceCounter].flowMap.size() << "\n     Flow count in trace " << traceCounter + 1 << " after:  ";

    for (auto mapit = traceVector[traceCounter].flowMap.begin(); mapit != traceVector[traceCounter].flowMap.end(); ){
        for (auto vecit = mapit->second.begin(); vecit != mapit->second.end(); ){
            if ( ( vecit->packets.size() < 100 ) && ( difftime(  mktime(&currentTime) , mktime(&vecit->packets[vecit->packets.size() - 1].first) ) > 300 ) ){
                vecit = mapit->second.erase(vecit);
            }
            else{
                ++vecit;
            }
        }
        if (mapit->second.size() == 0)
        {
            mapit = traceVector[traceCounter].flowMap.erase(mapit);
        }
        else{
            ++mapit;
        }
    }

    cout << traceVector[traceCounter].flowMap.size() << "\n";



}
void finalCleaning(int traceToClean ){
    // Called when a trace is completed. Deletes all flows having less than 100 packets

    cout << "Performing final cleaning on trace " << traceToClean + 1 << "...\n     Flow count in trace " << traceToClean + 1 << " before: " << traceVector[traceToClean].flowMap.size() << "\n     Flow count in trace " << traceToClean + 1 << " after:  ";


    for (auto mapit = traceVector[traceToClean].flowMap.begin(); mapit != traceVector[traceToClean].flowMap.end(); ){
        for (auto vecit = mapit->second.begin(); vecit != mapit->second.end(); ){
            if ( vecit->packets.size() < 100 ){
                vecit = mapit->second.erase(vecit);
            }
            else{
                ++vecit;
            }
        }
        if (mapit->second.size() == 0)
        {
            mapit = traceVector[traceToClean].flowMap.erase(mapit);
        }
        else{
            ++mapit;
        }
    }

    cout << traceVector[traceToClean].flowMap.size() << "\n";

}
void printFlowMap(){
    // Prints the map containing the flows (only used for testing purposes)
    ofstream myfile;
    myfile.open ("example.txt");

    int total;

    for (auto const& it : traceVector[traceCounter].flowMap){
        for ( int i = 0; i < it.second.size(); i++){
            //if (it.second[i].packets.size() > 100){
            total = total + it.second[i].packets.size();
            myfile << "\nFlow " <<
            (int)it.second[i].identifier.srcip.byte1 << "." <<
            (int)it.second[i].identifier.srcip.byte2 << "." <<
            (int)it.second[i].identifier.srcip.byte3 << "." <<
            (int)it.second[i].identifier.srcip.byte4 << ":" <<
            (int)it.second[i].identifier.srcport << " -> " <<
            (int)it.second[i].identifier.dstip.byte1 << "." <<
            (int)it.second[i].identifier.dstip.byte2 << "." <<
            (int)it.second[i].identifier.dstip.byte3 << "." <<
            (int)it.second[i].identifier.dstip.byte4 << ":" <<
            (int)it.second[i].identifier.dstport << " running ";
            switch(it.second[i].identifier.proto){
                case 0 :
                    myfile << "TCP/IP";
                    break;
                case 1 :
                    myfile << "UDP";
                    break;
                case 2 :
                    myfile << "ICMP";
                    break;
            }
            myfile << " contains " << it.second[i].packets.size() << " packets. Timestamps:\n";

            char timestr[32];
            for ( int j = 0; j < (it.second[i].packets).size(); j++ )
            {
                strftime( timestr, sizeof timestr, "   %x, %H:%M:%S", &(it.second[i].packets)[j].first);
                myfile << timestr << ":" << (it.second[i].packets)[j].second << "\n";
            }

        }//}

    }
    myfile << "\nTotal packets in flows: " << total;
}
void printTrace(){
    // Prints all traces to a text file
    ofstream myfile;
    myfile.open ("example.txt");

    int total;

    myfile << "Trace summary:\n";
    int counter = 0;
    for (auto traceit = traceVector.begin(); traceit != traceVector.end(); traceit++){
        myfile << "   Trace " << counter << " has ";
        total = 0;
        map<unsigned long long, vector<flow> >::iterator mapit;
        for ( mapit = traceit->flowMap.begin(); mapit != traceit->flowMap.end(); mapit++){
            total = total + mapit->second.size();
        }
        char timestr1[32], timestr2[32];
        strftime( timestr1, sizeof timestr1, "%x, %H:%M:%S", &traceit->starttime);
        strftime( timestr2, sizeof timestr2, "%x, %H:%M:%S", &traceit->endtime);
        myfile << total << " flows.\n     First packet seen at " << timestr1 << "\n     Last  packet seen at " << timestr2 << "\n     Duration of trace: ";
        int duration, seconds, hours, minutes;
        duration = difftime( mktime(&traceit->endtime) , mktime(&traceit->starttime));
        minutes = duration / 60;
        seconds = duration % 60;
        hours = minutes / 60;
        minutes = minutes % 60;
        myfile << hours << ":" << minutes << ":" << seconds << "\n";
        counter++;
    }

    int traceNumber = 0;
    for (auto traceit = traceVector.begin(); traceit != traceVector.end(); traceit++){
        myfile << "\n\n\n**************************** Trace " << traceNumber << " ****************************\n";
        for (auto const& it : traceit->flowMap){
            for ( int i = 0; i < it.second.size(); i++){
                //if (it.second[i].packets.size() > 100){
                total = total + it.second[i].packets.size();
                myfile << "\nFlow " <<
                (int)it.second[i].identifier.srcip.byte1 << "." <<
                (int)it.second[i].identifier.srcip.byte2 << "." <<
                (int)it.second[i].identifier.srcip.byte3 << "." <<
                (int)it.second[i].identifier.srcip.byte4 << ":" <<
                (int)it.second[i].identifier.srcport << " -> " <<
                (int)it.second[i].identifier.dstip.byte1 << "." <<
                (int)it.second[i].identifier.dstip.byte2 << "." <<
                (int)it.second[i].identifier.dstip.byte3 << "." <<
                (int)it.second[i].identifier.dstip.byte4 << ":" <<
                (int)it.second[i].identifier.dstport << " running ";
                switch(it.second[i].identifier.proto){ // Protocol numbers
                    case 6 :
                        myfile << "TCP/IP";
                        break;
                    case 17 :
                        myfile << "UDP";
                        break;
                    case 1 :
                        myfile << "ICMP";
                        break;
                    default:
                        myfile << "other protocol";
                        break;
                }
                myfile << " contains " << it.second[i].packets.size() << " packets. Timestamps:\n";

                char timestr[32];
                for ( int j = 0; j < (it.second[i].packets).size(); j++ )
                {
                    strftime( timestr, sizeof timestr, "   %x, %H:%M:%S", &(it.second[i].packets)[j].first);
                    myfile << timestr << ":" << (it.second[i].packets)[j].second << "\n";
                }

            }//}

        }
        traceNumber++;
    }
    myfile << "\nTotal packets in flows: " << total;

}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    /* Callback function invoked by libpcap for every incoming packet */

    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;


    ltime=localtime(&header->ts.tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    lastTime = currentTime;
    currentTime = *ltime;

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14);

    /* length of ethernet header */
    ip_len = (ih->ver_ihl & 0xf) * 4;

    /* retireve the position of the udp header */
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );


    /* If time difference between consecutive packets is more than 1 hour, create a new trace */
    if (difftime(mktime(&currentTime), mktime(&lastTime)) > 3600){
        cout << "\nNew trace identified...\n\n";
        traceVector.resize(traceVector.size() + 1);
        traceCounter++;
        traceVector[traceCounter - 1].numberofPackets = packetCount;
        packetCount = 0;
        traceVector[traceCounter - 1].endtime = lastTime;
        traceVector[traceCounter].starttime = currentTime;
        timetracker = currentTime;
        finalCleaning(traceCounter - 1);
    }

    /* Build flow identifier for this packet */
    flowIdentifier currentIdentifier;
    currentIdentifier.srcip = ih->saddr;
    currentIdentifier.dstip = ih->daddr;
    currentIdentifier.srcport = sport;
    currentIdentifier.dstport = dport;
    currentIdentifier.proto = ih->proto;

    unsigned long long hashValue = myHash(currentIdentifier);
    int foundFlow = 0;  // changes to 1 if a flow with the same identifier is found

    /* Search through flows having the same hashed flow identifier as the current packet */
    for ( int i = 0; i < traceVector[traceCounter].flowMap[hashValue].size(); i++){
        if (traceVector[traceCounter].flowMap[hashValue][i].identifier == currentIdentifier)
        {
            traceVector[traceCounter].flowMap[hashValue][i].packets.push_back(make_pair(*ltime, header->ts.tv_usec));
            foundFlow = 1;
            break;
        }

    }

    /* If no matching flow was found, make a new one */
    if (foundFlow == 0){
        flow tempflow;
        tempflow.identifier = currentIdentifier;
        (tempflow.packets).push_back(make_pair(*ltime, header->ts.tv_usec));
        traceVector[traceCounter].flowMap[hashValue].push_back(tempflow);
    }

    /* Initialize time tracker on the very first packet read */
    if (packetCount == 0){
        timetracker = *ltime;
        traceVector[traceCounter].starttime = currentTime;
    }

    /* clean flows in 30 minute packet intervals */
    if (difftime(mktime(ltime), mktime(&timetracker) ) > 1800){
        //counter++;
        //if (counter == 4){printFlowMap();}
        cleanFlowMap();
    }

    if (packetCount % 1000000 == 0){cout << packetCount << "   " << traceVector[traceCounter].flowMap.size() << "\n";}
    packetCount++;

}

int findVictim(ip_address ipToFind){
    // attempts to find an existing victim with the same source ip. Returns the index of the victim if found, -1 if not.
    for (int i = 0; i < traceVector[traceCounter].victimVector.size(); i++){
        if (traceVector[traceCounter].victimVector[i].victimIP == ipToFind){
            return i;
        }
    }
    return -1;
}
void analyzeTrace( trace &traceToAnalyze ){
    /* Forms victims for each trace by grouping together all flows having the same source ip address */

    // Iterate through the map corresponding to this trace
    cout << "Analyzing trace " << traceCounter << "...\n";
    for (auto mapit = traceToAnalyze.flowMap.begin(); mapit != traceToAnalyze.flowMap.end(); mapit++){
        // Iterate through the vector corresponding to this map entry
        for (auto vectorit = mapit->second.begin(); vectorit != mapit->second.end(); vectorit++){
            int victimFound = findVictim(vectorit->identifier.srcip); // attempts to find an existing victim with the same source ip. Returns the index of the victim if found, -1 if not.
            if (victimFound > -1){
                traceToAnalyze.victimVector[victimFound].victimFlows.push_back(*vectorit);
                if ( difftime( mktime(&traceToAnalyze.victimVector[victimFound].attackstart) , mktime(&vectorit->packets[0].first) ) > 0){
                    traceToAnalyze.victimVector[victimFound].attackstart = vectorit->packets[0].first;
                }
                if ( difftime( mktime(&traceToAnalyze.victimVector[victimFound].attackend) , mktime(&vectorit->packets[vectorit->packets.size() - 1].first) ) < 0 ){
                    traceToAnalyze.victimVector[victimFound].attackend = vectorit->packets[vectorit->packets.size() - 1].first;
                }
            }
            else if (victimFound == -1){
                victim newVictim;
                newVictim.victimIP = vectorit->identifier.srcip;
                newVictim.attackstart = vectorit->packets[0].first;
                newVictim.attackend = vectorit->packets[vectorit->packets.size() - 1].first;
                newVictim.victimFlows.push_back(*vectorit);
                traceToAnalyze.victimVector.push_back(newVictim);
            }
        }
    }
}


ifstream geolocation;

class GeoID {
    /* Geolocation tag */
public:
    string country, city, postalCode;
    float longitude, latitude; // Longitude: -180 to 180, Latitude: -90 to 90
    GeoID();
    GeoID(string cntry, string cty, string postal, float lttde, float lngtde);
};
GeoID::GeoID(){

}
GeoID::GeoID(string cntry, string cty, string postal, float lttde, float lngtde){
    country = cntry;
    city = cty;
    postalCode = postal;
    longitude = lngtde;
    latitude = lttde;
}
GeoID unknownID{"Unknown", "Unknown", "0",300,100};

unsigned int ipToInt(ip_address ip){
    /* Converts an ip address into its corresponding integer value */
    return ip.byte4 + (ip.byte3 <<  8) + (ip.byte2 << 16) + (ip.byte1 << 24);
}

int stringToInt(string convertThis){
    /* Converts a string into an integer since stoi isn't working */
    if (convertThis == ""){return 0;}
    istringstream ss(convertThis);
    int returnThis;
    ss >> returnThis;
    return returnThis;
}
float stringToFloat(string convertThis){
    /* Converts a float to an integer since stoi isn't working */
    if (convertThis == ""){return 0;}
    istringstream ss(convertThis);
    float returnThis;
    ss >> returnThis;
    return returnThis;
}

GeoID getGeoID( ip_address ip){
    /* Grabs the geolocation for an ip address from the database file, assumed to be already open in the "geolocation" stream */
    int ipAsInt = ipToInt(ip);
    string line, storage[7];
    while(getline(geolocation,line)){
        istringstream iss(line);
        for (int i = 0; i < 7; i++){
            getline(iss,storage[i],',');
        }
        if (stringToInt(storage[0]) <= ipAsInt){
            return GeoID(storage[2],storage[3],storage[4],stringToFloat(storage[5]),stringToFloat(storage[6]));
        }
    }
    return unknownID;

}

void printVictims(){
    /* Prints the list of victims in victimVector to the text file */
    ofstream myfile;
    myfile.open("example.txt"/*, std::ios_base::app*/);

    myfile << "\n\nVictim analysis:\n";
    int counter = 0;

    for (auto traceit = traceVector.begin(); traceit != traceVector.end(); traceit++){
        char timestr1[32], timestr2[32];
        strftime( timestr1, sizeof timestr1, "%x, %H:%M:%S", &traceit->starttime);
        strftime( timestr2, sizeof timestr2, "%x, %H:%M:%S", &traceit->endtime);
        int duration, seconds, hours, minutes;
        duration = difftime( mktime(&traceit->endtime) , mktime(&traceit->starttime));
        minutes = duration / 60;
        seconds = duration % 60;
        hours = minutes / 60;
        minutes = minutes % 60;
        //myfile << "Trace duration: " << hours << ":" << minutes << ":" << seconds << "\n";
        myfile << "\n\nTrace " << counter << " had " << traceit->victimVector.size() << " victims with " << traceit->numberofPackets << " packets total.\nTrace time is " << timestr1 << " until " << timestr2 << " (" << hours << ":" << minutes << ":" << seconds << " duration)\n";
        for (auto victimit = traceit->victimVector.begin(); victimit != traceit->victimVector.end(); victimit++){
            string ipoutput = SSTR((int)victimit->victimIP.byte1);
            ipoutput.append(".");
            ipoutput.append(SSTR((int)victimit->victimIP.byte2));
            ipoutput.append(".");
            ipoutput.append(SSTR((int)victimit->victimIP.byte3));
            ipoutput.append(".");
            ipoutput.append(SSTR((int)victimit->victimIP.byte4));
            myfile << "   " << setw(15) << ipoutput << " saw " << setw(3) << victimit->victimFlows.size() << " flows, having ";
            int totalVictimPackets = 0;
            for ( int i = 0; i < victimit->victimFlows.size(); i++){
                totalVictimPackets += victimit->victimFlows[i].packets.size();
            }
            char timestr1[32], timestr2[32];
            strftime( timestr1, sizeof timestr1, "%x, %H:%M:%S", &victimit->attackstart);
            strftime( timestr2, sizeof timestr2, "%x, %H:%M:%S", &victimit->attackend);
            int attackduration = difftime(mktime(&victimit->attackend), mktime(&victimit->attackstart));
            myfile << totalVictimPackets << " total packets.\n          Attack started: "
                << timestr1 << "\n          Attack ended: " << timestr2 << "\n          Total duration (seconds): " << attackduration;
            myfile << "\n          Rate: " << totalVictimPackets / (float)attackduration << " packets per second on average\n";
            GeoID currentID = getGeoID(victimit->victimIP);
            myfile << "          Country: " << currentID.country << "\n          City: " << currentID.city;
            if ( currentID.longitude == 100 && currentID.latitude == 300){
                myfile << "\n          Postal code:\n          Longitude:\n          Latitude:\n";
            }
            else{
                myfile << "\n          Postal code: " << currentID.postalCode << "\n          Longitude:" << currentID.longitude << "\n          Latitude: " << currentID.latitude << "\n";
            }

        }
        counter++;
    }

}

int main()
{
    /* path to geolocation file */
    //geolocation.open("C:\\Users\\hutchinsona2013\\Desktop\\geolocationupdated.csv");

    /* path to pcap file */
    string file = "C:\\Users\\hutchinsona2013\\Desktop\\SkypeIRC.cap";

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);


    pcap_loop( pcap, -1, packet_handler, NULL);
    traceVector[traceCounter].endtime = currentTime;
    traceVector[traceCounter].numberofPackets = packetCount;

    // Clean the last trace
    finalCleaning(traceCounter);

    // Find victims for traces
    traceCounter = 0;
    for (auto traceit = traceVector.begin(); traceit != traceVector.end(); traceit++){
        analyzeTrace(*traceit);
        traceCounter++;
    }

    printVictims();





    return 0;

}
