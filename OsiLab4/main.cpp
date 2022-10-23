#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <iomanip>
#include <string>
#include <sstream>

using namespace std;

// Мэп, где храним основные 4 типа фреймов и то, сколько раз он встретился в файле
map<string, int> frameTypesUses = { {"LLC", 0}, {"RAW", 0}, {"DIX", 0}, {"SNAP", 0} };
// Мэп, где храним основные 3 вида дейтаграмм, лежащих внутри фреймов
map<string, int> dataTypesUses = { {"IP", 0}, {"ARP",0}, {"RARP", 0} };

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
      s << hex << toupper;
      for (int i = 0; i < 5; i++)
      {
         s << address[i] << " : ";
      }
      s << address[5];
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
      s << hex << toupper;
      for (int i = 0; i < 3; i++)
      {
         s << address[i] << ".";
      }
      s << address[3];
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
   dest = IpAddress::Parse(data, begin + 12);
   source = IpAddress::Parse(data, begin + 16);

   return (static_cast<uint16_t>(data[begin + 2]) << 8) + data[begin + 3];
}

uint16_t ArpDataGet(vector<uint8_t>& data, size_t begin, IpAddress& dest, IpAddress& source, MacAddress& destMac, MacAddress& sourceMac) {
   uint8_t hardwareLen = data[begin + 4];
   uint8_t protocolLen = data[begin + 5];
   if (protocolLen == 4)
   {
      destMac = MacAddress::Parse(data, begin + 8);
      dest = IpAddress::Parse(data, begin + 8 + hardwareLen);

      sourceMac = MacAddress::Parse(data, begin + 8 + hardwareLen + protocolLen);
      source = IpAddress::Parse(data, begin + 8 + 2 * hardwareLen + protocolLen);

      return 2 * hardwareLen + 2 * protocolLen + 8;
   }
   else
   {
      throw exception("Not implemented ARP data parcer for protocol non IPv4");
   }
}

void FrameParser(vector<uint8_t>& data) {
   size_t dataPtr = 0;
   size_t framesCount = 0;
   while (dataPtr < data.size())
   {
      cout << endl << " **************************************" << endl;

      framesCount++;
      cout << "Фрейм #" << framesCount << ": " << endl;

      // Считываем мак-адреса очередного фрейма, по 6 байт каждый
      auto destAddr = MacAddress::Parse(data, dataPtr);
      dataPtr += 6;
      auto sourceAddr = MacAddress::Parse(data, dataPtr);
      dataPtr += 6;
      cout << "  MAC-адрес приёмника: " << destAddr.ToString() << endl;
      cout << "  MAC-адрес источника: " << sourceAddr.ToString() << endl;

      // Считываем переменную длины/типа данных фрейма, два байта
      uint16_t LT = (static_cast<uint16_t>(data[dataPtr]) << 8) + data[dataPtr + 1];
      dataPtr += 2;
      // Если LT больше максимального числа элементов в данных фрейма, то он не длина, а тип данных
      // то есть это - протокол Ethernet II (DIX)
      if (LT > 0x05DC)
      {
         cout << "  Тип фрейма: Ethernet II (DIX)" << endl;
         frameTypesUses["DIX"]++;

         if (LT == 0x0800)
         {
            cout << "  Фрейм использует: IP-дейтаграмму" << endl;
            dataTypesUses["IP"]++;

            IpAddress destIp{};
            IpAddress sourceIp{};
            // Получаем из структуры данных IP длину данных, чтобы перейти к следующему фрейму
            LT = IpDataGet(data, dataPtr, destIp, sourceIp);

            cout << "  IP адрес приёмника: " << destIp.ToString() << endl;
            cout << "  IP адрес источника: " << sourceIp.ToString() << endl;
            cout << "  Длина фрейма: " << LT << endl;
         }
         else if (LT == 0x0806)
         {
            cout << "  Фрейм использует: ARP-дейтаграмму" << endl;
            dataTypesUses["ARP"]++;

            IpAddress destIp{};
            IpAddress sourceIp{};
            MacAddress destMac{};
            MacAddress sourceMac{};
            // Получаем из структуры данных ARP длину данных, чтобы перейти к следующему фрейму
            LT = ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

            cout << "  MAC-адрес приёмника по ARP: " << destMac.ToString() << endl;
            cout << "  IP адрес приёмника: " << destIp.ToString() << endl;
            cout << "  MAC-адрес источника по ARP: " << sourceAddr.ToString() << endl;
            cout << "  IP адрес источника: " << sourceIp.ToString() << endl;
            cout << "  Длина фрейма: " << LT << endl;
         }
         else if (LT == 0x0835)
         {
            cout << "  Фрейм использует: RARP-дейтаграмму" << endl;
            dataTypesUses["RARP"]++;

            IpAddress destIp{};
            IpAddress sourceIp{};
            MacAddress destMac{};
            MacAddress sourceMac{};
            // Получаем из структуры данных RARP длину данных, чтобы перейти к следующему фрейму
            // (т.к. ARP от RARP отличается лишь значением Operation (7-8 bit), то можно юзать тот же метод)
            LT = ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

            cout << "  MAC-адрес приёмника по RARP: " << destMac.ToString() << endl;
            cout << "  IP адрес приёмника: " << destIp.ToString() << endl;
            cout << "  MAC-адрес источника по RARP: " << sourceAddr.ToString() << endl;
            cout << "  IP адрес источника: " << sourceIp.ToString() << endl;
            cout << "  Длина фрейма: " << LT << endl;
         }
      }
      else
      {
         // Иначе есть 3 варианта: Raw, LLC и SNAP
         // LT в данном случае является оставшейся длиной фрейма

         // Если первые 2 байта данных равны FF, то это Raw
         if (data[dataPtr] == 0xFF && data[dataPtr + 1] == 0xFF)
         {
            cout << "  Тип фрейма: Raw 802.3 (Novell)" << endl;
            frameTypesUses["RAW"]++;
            cout << "  Длина фрейма: " << LT << endl;
            // Novell рассчитан под данные формата IPX, а это надо что-то ещё изучать, лениво
         }
         else if (data[dataPtr] == 0xAA && data[dataPtr + 1] == 0xAA)
         {
            cout << "  Тип фрейма: Ethernet 802.3 (with SNAP)" << endl;
            frameTypesUses["SNAP"]++;

            uint16_t dataType = (static_cast<uint16_t>(data[dataPtr + 6]) << 8) + data[dataPtr + 7];

            if (dataType == 0x0800)
            {
               cout << "  Фрейм использует: IP-дейтаграмму" << endl;
               dataTypesUses["IP"]++;

               IpAddress destIp{};
               IpAddress sourceIp{};

               IpDataGet(data, dataPtr, destIp, sourceIp);

               cout << "  IP адрес приёмника: " << destIp.ToString() << endl;
               cout << "  IP адрес источника: " << sourceIp.ToString() << endl;
               cout << "  Длина фрейма: " << LT << endl;
            }
            else if (dataType == 0x0806)
            {
               cout << "  Фрейм использует: ARP-дейтаграмму" << endl;
               dataTypesUses["ARP"]++;

               IpAddress destIp{};
               IpAddress sourceIp{};
               MacAddress destMac{};
               MacAddress sourceMac{};

               ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

               cout << "  MAC-адрес приёмника по ARP: " << destMac.ToString() << endl;
               cout << "  IP адрес приёмника: " << destIp.ToString() << endl;
               cout << "  MAC-адрес источника по ARP: " << sourceAddr.ToString() << endl;
               cout << "  IP адрес источника: " << sourceIp.ToString() << endl;
               cout << "  Длина фрейма: " << LT << endl;
            }
            else if (dataType == 0x0835)
            {
               cout << "  Фрейм использует: RARP-дейтаграмму" << endl;
               dataTypesUses["RARP"]++;

               IpAddress destIp{};
               IpAddress sourceIp{};
               MacAddress destMac{};
               MacAddress sourceMac{};

               // (т.к. ARP от RARP отличается лишь значением Operation (7-8 bit), то можно юзать тот же метод)
               ArpDataGet(data, dataPtr, destIp, sourceIp, destMac, sourceMac);

               cout << "  MAC-адрес приёмника по RARP: " << destMac.ToString() << endl;
               cout << "  IP адрес приёмника: " << destIp.ToString() << endl;
               cout << "  MAC-адрес источника по RARP: " << sourceAddr.ToString() << endl;
               cout << "  IP адрес источника: " << sourceIp.ToString() << endl;
               cout << "  Длина фрейма: " << LT << endl;
            }
         }
         else
         {
            cout << "  Тип фрейма: Ethernet 802.3 (LLC)" << endl;
            frameTypesUses["LLC"]++;
            cout << "  Длина фрейма: " << LT << endl;
            // LLC без понятия как работает с данными, что-то они там намутили, надо копаться, лениво
         }
      }

      dataPtr += LT;
   }
}

int main() {
   setlocale(LC_ALL, "ru-RU");

   cout << "Введите название файла с фреймами: ";
   string inpFileName;
   cin >> inpFileName;
   // Файл входных данных
   auto inpFile = ifstream(inpFileName, ios::binary);

   if (!inpFile.is_open())
   {
      cout << "Ошибка открытия файла. Программа завершается." << endl;
      return -1;
   }
   // Получаем длину файла
   inpFile.seekg(0, ios_base::end);
   size_t inpFileSize = inpFile.tellg();
   inpFile.seekg(0);

   // Вектор байтов из файла
   vector<uint8_t> data(inpFileSize);
   // Читаем массив из файла
   for (size_t i = 0; i < inpFileSize; i++)
   {
      inpFile >> data[i];
   }
   inpFile.close();

   FrameParser(data);

   return 0;
}