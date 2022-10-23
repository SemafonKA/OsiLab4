#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <iomanip>
#include <string>
#include <sstream>

using namespace std;

// ���, ��� ������ �������� 4 ���� ������� � ��, ������� ��� �� ���������� � �����
map<string, int> frameTypesUses = { {"LLC", 0}, {"RAW", 0}, {"DIX", 0}, {"SNAP", 0} };
// ���, ��� ������ �������� 3 ���� ����������, ������� ������ �������
map<string, int> dataTypesUses = { {"IP", 0}, {"ARP",0}, {"RARP", 0} };

size_t framesCount = 0;

class MacAddress {
public:
   uint8_t address[6] = { 0 };

   MacAddress& operator= (MacAddress& right) {
      for (int i = 0; i < 6; i++)
      {
         this->address[i] = right.address[i];
      }
      return *this;
   }

   MacAddress& operator= (MacAddress&& right) noexcept {
      swap(this->address, right.address);
      return *this;
   }

   MacAddress() {};

   MacAddress(MacAddress& right) noexcept {
      (*this) = right;
   }
   MacAddress(MacAddress&& right) noexcept {
      (*this) = right;
   }

   string ToString() const noexcept {
      stringstream s;
      s.unsetf(ios::dec);
      s.setf(ios::hex | ios::uppercase);
      for (int i = 0; i < 5; i++)
      {
         // ��������� ����� ������ ������������ uint8_t ��� uchar, �� �� �� ������� �� � 16-������ ����
         s << setw(2) << setfill('0') << static_cast<int>(address[i]) << " : ";
      }
      s << setw(2) << setfill('0') << static_cast<int>(address[5]);
      return s.str();
   }

   static MacAddress Parse(vector<uint8_t>& data, size_t begin) {
      MacAddress adr;
      for (int i = 0, j = begin; i < 6; i++, j++)
      {
         adr.address[i] = data[j];
      }
      return adr;
   }
};

class IpAddress {
public:

   uint8_t address[4] = { 0 };

   IpAddress& operator= (IpAddress& right) {
      for (int i = 0; i < 4; i++)
      {
         this->address[i] = right.address[i];
      }
      return *this;
   }

   IpAddress& operator= (IpAddress&& right) noexcept {
      swap(this->address, right.address);
      return *this;
   }

   IpAddress(IpAddress& right) noexcept {
      (*this) = right;
   }
   IpAddress(IpAddress&& right) noexcept {
      (*this) = right;
   }
   IpAddress() {};

   string ToString() const noexcept {
      stringstream s;
      for (int i = 0; i < 3; i++)
      {
         s << static_cast<int>(address[i]) << ".";
      }
      s << static_cast<int>(address[3]);
      return s.str();
   }

   static IpAddress Parse(vector<uint8_t>& data, size_t begin) {
      IpAddress ip;
      for (int i = 0, j = begin; i < 4; i++, j++)
      {
         ip.address[i] = data[j];
      }
      return ip;
   }
};

uint16_t IpDataGet(vector<uint8_t>& data, size_t begin, IpAddress& dest, IpAddress& source) {
   source = IpAddress::Parse(data, begin + 12);
   dest = IpAddress::Parse(data, begin + 16);

   return (static_cast<uint16_t>(data[begin + 2]) << 8) + data[begin + 3];
}

uint16_t ArpDataGet(vector<uint8_t>& data, size_t begin, IpAddress& dest, IpAddress& source, MacAddress& destMac, MacAddress& sourceMac) {
   uint8_t hardwareLen = data[begin + 4];
   uint8_t protocolLen = data[begin + 5];
   if (protocolLen == 4)
   {
      sourceMac = MacAddress::Parse(data, begin + 8);
      source = IpAddress::Parse(data, begin + 8 + hardwareLen);

      destMac = MacAddress::Parse(data, begin + 8 + hardwareLen + protocolLen);
      dest = IpAddress::Parse(data, begin + 8 + 2 * hardwareLen + protocolLen);

      return 2 * hardwareLen + 2 * protocolLen + 8;
   }
   else
   {
      throw exception("Not implemented ARP data parcer for protocol non IPv4");
   }
}

void FrameParser(vector<uint8_t>& data) {
   size_t dataPtr = 0;
   while (dataPtr < data.size())
   {
      cout << endl << " **************************************" << endl << endl;

      framesCount++;
      cout << "����� #" << framesCount << ": " << endl;

      // ��������� ���-������ ���������� ������, �� 6 ���� ������
      auto destAddr = MacAddress::Parse(data, dataPtr);
      dataPtr += 6;
      auto sourceAddr = MacAddress::Parse(data, dataPtr);
      dataPtr += 6;
      cout << "  MAC-����� ��������: " << destAddr.ToString() << endl;
      cout << "  MAC-����� ���������: " << sourceAddr.ToString() << endl;

      // ��������� ���������� �����/���� ������ ������, ��� �����
      uint16_t LT = (static_cast<uint16_t>(data[dataPtr]) << 8) + data[dataPtr + 1];
      dataPtr += 2;
      // ���� LT ������ ������������� ����� ��������� � ������ ������, �� �� �� �����, � ��� ������
      // �� ���� ��� - �������� Ethernet II (DIX)
      if (LT > 0x05DC)
      {
         cout << "  ��� ������: Ethernet II (DIX)" << endl;
         frameTypesUses["DIX"]++;

         if (LT == 0x0800)
         {
            cout << "  ����� ����������: IP-�����������" << endl;
            dataTypesUses["IP"]++;

            IpAddress destIp{};
            IpAddress sourceIp{};
            // �������� �� ��������� ������ IP ����� ������, ����� ������� � ���������� ������
            LT = IpDataGet(data, dataPtr, destIp, sourceIp);

            cout << "  IP ����� ��������: " << destIp.ToString() << endl;
            cout << "  IP ����� ���������: " << sourceIp.ToString() << endl;
            cout << "  ����� ������: " << LT << endl;
         }
         else if (LT == 0x0806)
         {
            cout << "  ����� ����������: ARP-�����������" << endl;
            dataTypesUses["ARP"]++;

            IpAddress destIp{};
            IpAddress sourceIp{};
            MacAddress destMac{};
            MacAddress sourceMac{};
            // �������� �� ��������� ������ ARP ����� ������, ����� ������� � ���������� ������
            LT = ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

            cout << "  MAC-����� �������� �� ARP: " << destMac.ToString() << endl;
            cout << "  IP ����� ��������: " << destIp.ToString() << endl;
            cout << "  MAC-����� ��������� �� ARP: " << sourceMac.ToString() << endl;
            cout << "  IP ����� ���������: " << sourceIp.ToString() << endl;
            cout << "  ����� ������: " << LT << endl;
         }
         else if (LT == 0x0835)
         {
            cout << "  ����� ����������: RARP-�����������" << endl;
            dataTypesUses["RARP"]++;

            IpAddress destIp{};
            IpAddress sourceIp{};
            MacAddress destMac{};
            MacAddress sourceMac{};
            // �������� �� ��������� ������ RARP ����� ������, ����� ������� � ���������� ������
            // (�.�. ARP �� RARP ���������� ���� ��������� Operation (7-8 bit), �� ����� ����� ��� �� �����)
            LT = ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

            cout << "  MAC-����� �������� �� RARP: " << destMac.ToString() << endl;
            cout << "  IP ����� ��������: " << destIp.ToString() << endl;
            cout << "  MAC-����� ��������� �� RARP: " << sourceAddr.ToString() << endl;
            cout << "  IP ����� ���������: " << sourceIp.ToString() << endl;
            cout << "  ����� ������: " << LT << endl;
         }
      }
      else
      {
         // ����� ���� 3 ��������: Raw, LLC � SNAP
         // LT � ������ ������ �������� ���������� ������ ������

         // ���� ������ 2 ����� ������ ����� FF, �� ��� Raw
         if (data[dataPtr] == 0xFF && data[dataPtr + 1] == 0xFF)
         {
            cout << "  ��� ������: Raw 802.3 (Novell)" << endl;
            frameTypesUses["RAW"]++;
            cout << "  ����� ������: " << LT << endl;
            // Novell ��������� ��� ������ ������� IPX, � ��� ���� ���-�� ��� �������, ������
         }
         else if (data[dataPtr] == 0xAA && data[dataPtr + 1] == 0xAA)
         {
            cout << "  ��� ������: Ethernet 802.3 (with SNAP)" << endl;
            frameTypesUses["SNAP"]++;

            uint16_t dataType = (static_cast<uint16_t>(data[dataPtr + 6]) << 8) + data[dataPtr + 7];

            if (dataType == 0x0800)
            {
               cout << "  ����� ����������: IP-�����������" << endl;
               dataTypesUses["IP"]++;

               IpAddress destIp{};
               IpAddress sourceIp{};

               IpDataGet(data, dataPtr, destIp, sourceIp);

               cout << "  IP ����� ��������: " << destIp.ToString() << endl;
               cout << "  IP ����� ���������: " << sourceIp.ToString() << endl;
               cout << "  ����� ������: " << LT << endl;
            }
            else if (dataType == 0x0806)
            {
               cout << "  ����� ����������: ARP-�����������" << endl;
               dataTypesUses["ARP"]++;

               IpAddress destIp{};
               IpAddress sourceIp{};
               MacAddress destMac{};
               MacAddress sourceMac{};

               ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

               cout << "  MAC-����� �������� �� ARP: " << destMac.ToString() << endl;
               cout << "  IP ����� ��������: " << destIp.ToString() << endl;
               cout << "  MAC-����� ��������� �� ARP: " << sourceAddr.ToString() << endl;
               cout << "  IP ����� ���������: " << sourceIp.ToString() << endl;
               cout << "  ����� ������: " << LT << endl;
            }
            else if (dataType == 0x0835)
            {
               cout << "  ����� ����������: RARP-�����������" << endl;
               dataTypesUses["RARP"]++;

               IpAddress destIp{};
               IpAddress sourceIp{};
               MacAddress destMac{};
               MacAddress sourceMac{};

               // (�.�. ARP �� RARP ���������� ���� ��������� Operation (7-8 bit), �� ����� ����� ��� �� �����)
               ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

               cout << "  MAC-����� �������� �� RARP: " << destMac.ToString() << endl;
               cout << "  IP ����� ��������: " << destIp.ToString() << endl;
               cout << "  MAC-����� ��������� �� RARP: " << sourceAddr.ToString() << endl;
               cout << "  IP ����� ���������: " << sourceIp.ToString() << endl;
               cout << "  ����� ������: " << LT << endl;
            }
         }
         else
         {
            cout << "  ��� ������: Ethernet 802.3 (LLC)" << endl;
            frameTypesUses["LLC"]++;
            cout << "  ����� ������: " << LT << endl;
            // LLC ��� ������� ��� �������� � �������, ���-�� ��� ��� ��������, ���� ��������, ������
         }
      }

      dataPtr += LT;
   }
}

int main() {
   setlocale(LC_ALL, "ru-RU");

   cout << "������� �������� ����� � ��������: ";
   string inpFileName;
   cin >> inpFileName;
   // ���� ������� ������
   auto inpFile = ifstream(inpFileName, ios::binary);

   if (!inpFile.is_open())
   {
      cout << "������ �������� �����. ��������� �����������." << endl;
      return -1;
   }
   // �������� ����� �����
   inpFile.seekg(0, ios_base::end);
   size_t inpFileSize = inpFile.tellg();
   inpFile.seekg(0);

   // ������ ������ �� �����
   vector<uint8_t> data(istreambuf_iterator<char>(inpFile), {});
   inpFile.close();

   FrameParser(data);

   cout << endl << " **************************************" << endl << endl;
   cout << "����������: " << endl;
   cout << "����� �������: " << framesCount << ", �� ���: " << endl;
   cout << " - Ethernet II (DIX): " << frameTypesUses["DIX"] << endl;
   cout << " - Raw 802.3 (Novell): " << frameTypesUses["RAW"] << endl;
   cout << " - Ethernet 802.3 (with SNAP): " << frameTypesUses["SNAP"] << endl;
   cout << " - Ethernet 802.3 (LLC): " << frameTypesUses["LLC"] << endl << endl;

   cout << "��� ���� ��������� ������ �������������� ��������� �������: " << endl;
   cout << " - IP-�����������: " << dataTypesUses["IP"] << endl;
   cout << " - ARP-�����������: " << dataTypesUses["ARP"] << endl;
   cout << " - RARP-�����������: " << dataTypesUses["RARP"] << endl << endl;
   return 0;
}