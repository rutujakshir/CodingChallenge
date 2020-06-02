#CodingChallenge

#include <iostream>
#include <string>
#include <fstream>
#include <map>

using namespace std;

class Firewall{
    
    private:
    //map to store the rules
    map<string,map<string,map<int,string>>> hmap;
    
    public:
    Firewall(string file_path){
        
        //open CSV file which contains the "allow" rules
        ifstream ip(file_path);
        
       //read and store data
       //store data in a nested map
       //map: key1-direction, key2-prtocol, key3-port#, value3- IP
       //range inclusive-create seperate key3 for each range in the port
        
        hmap.clear();
        
        while(ip.good()){
            
            string direction;
            string protocol;
            string port;
            string address; //IP address
            
            //read a line from the file
            getline(ip,direction,',');
            getline(ip,protocol,',');
            getline(ip,port,',');
            getline(ip,address,'\n');
            
            //check if port is a range or not
            string port1,port2;
            
            for(int i = 0;i<port.size();i++){
                if(port[i]=='-'){
                    int j=i;
                    
                    
                    //port1 contains first port in the range
                    for(int k =0; k<j;k++){
                        port1[k]=port[k];
                    }
                    
                    //port2 contains second port in the range
                    for(int l=j+1;l<port.size();l++){
                        port2[l-j-1]=port[l];
                    }
                    
                }
                else{
                    port1=port;
                    port2=port;
                }
                
            }
            
            //convert port from string to integer
            int port1_int,port2_int,range;
            port1_int = stoi(port1);
            port2_int = stoi(port2);
            range = port2_int - port1_int;
            
            //store in map
            for(int m=0; m<=range;m++){
                int p=port1_int + m;
                hmap[direction][protocol][p] = address;
            }
            
            //do not split the IP range to reduce space complexity
            //address this while 
         }
        
        ip.close();
    }
    
    //code snippet found online to convert an IP to integer
    uint32_t IPToUInt(const string ip) {
        int a, b, c, d;
        uint32_t addr = 0;

        if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
            return 0;

        addr = a << 24;
        addr |= b << 16;
        addr |= c << 8;
        addr |= d;
        return addr;
   }
    
    //function to check if IP is in range: modified from an online snippet
    bool IsIPInRange(const string ip, const string start_ip_range, const string end_ip_range) {
    uint32_t ip_addr = IPToUInt(ip);
    uint32_t start_addr = IPToUInt(start_ip_range);
    uint32_t end_addr = IPToUInt(end_ip_range);

    if (ip_addr >= start_addr && ip_addr <= end_addr)
        return true;
    return false;
    }
    
    
    bool accept_packet(string direction, string protocol, int port, string address){
        
        //check if IP in the rule(stored in map) is a range or not 
        string IP = "empty"; 
        string IP1,IP2;
        
        if (hmap[direction][protocol].count(port) > 0){
            IP = hmap[direction][protocol][port];
        }
        if (IP == "empty"){
            //if direction, protocol, port do not match return false
            return false;
        }
        else{
            
            for (int i=0; i<IP.size();i++){
                if(IP[i]=='-'){
                    int j=i;
                    
                    
                    //IP1 contains first IP in the range
                    for(int k =0; k<j;k++){
                        IP1[k]=IP[k];
                    }
                    
                    //IP2 contains second IP in the range
                    for(int l=j+1;l<IP.size();l++){
                        IP2[l-j-1]=IP[l];
                    }
                    
                }
                else{
                    IP1=IP;
                    IP2=IP;
                }
            }
        }
        
        //check if IP is in the range
        bool b = IsIPInRange(address, IP1, IP2);
        
        return b;
    } 
    
};

int main()
{
    string file_path = "https://drive.google.com/drive/u/1/my-drive/sample.csv";
    
    Firewall fw(file_path);
    
    //test cases
    
    bool b1 = fw.accept_packet("inbound", "tcp", 80, "192.168.1.2");
    cout << b1;
    bool b2 = fw.accept_packet("inbound", "udp", 53, "192.168.2.1");
    cout<< b2;
    bool b3 = fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11");
    cout << b3;
    bool b4 = fw.accept_packet("inbound", "tcp", 81, "192.168.1.2");
    cout << b4;
    bool b5 = fw.accept_packet("inbound", "udp", 24, "52.12.48.92");
    cout << b5;
    
    return 0;
}

// sample rules:

//inbound,tcp,80,192.168.1.2	
//outbound,tcp,10000-20000,192.168.10.11	
//inbound,udp,53,192.168.1.1-192.168.2.5	
//outbound,udp,1000-2000,52.12.48.92	
//inbound,tcp,1000-2000,192.168.1.1-192.168.2.5	
