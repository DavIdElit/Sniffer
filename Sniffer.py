#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      dapabla
#
# Created:     23/05/2022
# Copyright:   (c) DonutMcGordo 2022
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import socket

# the public network interface
HOST = socket.gethostbyname(socket.gethostname())
#HOST= 192.168.56.1

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


def L8ToL16(Lista8):

      L = len(Lista8)                    # Obtiene longitud de la lista
      if L%2 != 0:                       # Si longitud es impar
        Lista8.append(0)               #    añade un elemento nulo
      L16 = []                           # Inicializa Lista de words (vacía)
      for i in range(0,L,2):          # Recorre la lista de bytes de 2 en 2 bytes
        L16 = L16 + [(Lista8[i] << 8) | (Lista8[i+1])]  # Construye word y la añade a la lista
      return L16

def checksum(datos):
       suma = sum(datos)                  # Suma todos los elementos de una lista
       suma = suma//65536 + suma%65536    # Calcula suma con carry para 16 bits
       suma = 65535-suma                  # Complemento a uno para 16 bits
       return suma                        # Devuelve el checksum



#Definimos función para TCP
def cabecera_TCP(DatosIP):

    #Dividimos cabecera y datos
    CabeceraTCP = DatosIP[:20]
    DatosTCP = DatosIP[20:]

    #Desglosamos la cabecera TCP
    src_port = (CabeceraTCP[0] << 8) | CabeceraTCP[1]           #Puerto origen
    dst_port = (CabeceraTCP[2] << 8) | CabeceraTCP[3]           #Puerto destino
    sequence_number = CabeceraTCP[4] >> 32                      #Número de secuencia
    acknowledgment_number = CabeceraTCP[6] >>32                 #Número de reconocimiento
    header_length = CabeceraTCP[12] >> 4                        #Longitud de la cabecera(20 bytes sin opciones)
    reservado = CabeceraTCP[12] & 0xF

    #Obtenemos las flags
    Flags = CabeceraTCP[13] << 2
    URG = Flags & 0b10000000
    ACK = Flags & 0b01000000
    PSH = Flags & 0b00100000
    RST = Flags & 0b00010000
    SYN = Flags & 0b00001000
    FIN = Flags & 0b00000100

    checksum_recibido = hex(CabeceraTCP[16]*256 + CabeceraTCP[17])
    punteroDatos = CabeceraTCP[18] >> 16


    #Mostrar por pantalla los campos del segmento TCP
    print('\n\t -TCP Segment: ')
    print('\t\t -Source Port: ',src_port)
    print('\t\t -Destination Port: ', dst_port)
    print('\t\t -Sequence Number: ', sequence_number)
    print('\t\t -Aclnowledgment Number: ', acknowledgment_number)
    print('\t\t -Header Length: ', header_length*4, bytes)

    #Ahora mostramos las flags activas dentro del segmento
    if URG == 0b10000000:
        print('\t\t -FLag: ', URG)
    if ACK == 0b01000000:
        print('\t\t -Flag: ', ACK)
    if PSH == 0b00100000:
        print('\t\t -Flag: ', PSH)
    if RST == 0b00010000:
        print('\t\t -Flag: ', RST)
    if SYN == 0b00001000:
        print('\t\t -Flag: ', SYN)
    if FIN == 0b00000100:
        print('\t\t -Flag: ', FIN)

    print('\t\t -Checksum(recibido): ', checksum_recibido)
    print('\t\t -Puntero a Datos Urgentes: ', punteroDatos)


#Definimos la funcion para ICMP
def cabecera_ICMP(DatosIP):

    #Dividimos cabecera y datos
    CabeceraICMP = DatosIP[:8]
    DatosICMP = DatosIP[8:]

    #Desglosamos los datos de la cabecera ICMP
    tipo= CabeceraICMP[0]
    codigo=CabeceraICMP[1]
    checksum=(CabeceraICMP[2] << 8) | CabeceraICMP[3]


    #Mostramos los datos de la cabecera ICMP
    print('\n\t -ICMP Packet:')
    print('\t\t -Tipo=',tipo,', ', 'Codigo= ',codigo,', ','Checksum= ',hex(checksum))

    if tipo==0:
        print('\t\t -Respuesta de eco a un comando ping.')
    elif tipo==3:
        print('\t\t -Destino inalcanzable.')
    elif tipo==8:
        print('\t\t -Petición de eco.')
    elif tipo==11:
        print('\t\t -Tiempo excedido en datagrama.')


#Definimos la funcion para ICMP
def cabecera_UDP(DatosIP):

    #Obtenemos la cabecera UDP
    CabeceraUDP=DatosIP[:8]
    DatosUDP=DatosIP[8:]


    #Desglosamos los datos de la cabecera UDP
    src_port=(CabeceraUDP[0] << 8) | CabeceraUDP[1]     #Puerto origen del paquete
    dest_port=(CabeceraUDP[2] << 8) | CabeceraUDP[3]    #Puerto destino del paquete
    length=(CabeceraUDP[4] << 8) | CabeceraUDP[5]
    checksumUDP = hex(CabeceraUDP[6]*256 +  CabeceraUDP[7]) #Checksum recibido


    # Construye lista con Pseudocabecera UDP, Cabecera UDP y Datos UDP
    DatosB=CabeceraIP[12:20] + [0] + [17] + CabeceraUDP[4:6] + CabeceraUDP + DatosUDP

    # Borra el checksum (para que no forme parte del cálculo)
    DatosB[18] = 0
    DatosB[19] = 0

    # Convierte lista de bytes en lista de words
    DatosW = L8ToL16(DatosB)

    ##checksum_calculado= hex(checksum(L8ToL16(DatosB)))

     #Mostramos los datos de la cabecera UDP
    print('\n\t -UDP Packet:')
    print('\t\t -Pseudocabecera UDP= ',DatosB[0:12])
    print('\t\t -Cabecera UDP= ',DatosB[12:20])
    print('')
    print('\t\t -Source Port= ',src_port,', ','Destination Port= ',dest_port)
    print('\t\t -Length= ',length)
    print('\t\t -Checksum(recibido)= ',hex(CabeceraUDP[6]*256 +  CabeceraUDP[7]))   #Suma de verificacion recibida en la cabecera UDP
    ##print('\t\t -Checksum(calculado)= ',checksum_calculado)

    if dest_port==53:               #si el puerto de destino es 53 entonces es un mensaje de dominio(DNS)

        cabecera_DNS(DatosUDP)          #ejecutamos la función para que muestre los datos de la cabecera DNS

    if src_port==53:
        cabecera_DNS(DatosUDP)          #ejecutamos la función para que muestre los datos de la cabecera DNS



#Definimos la funcion para ICMP
def cabecera_DNS(DatosUDP):

    CabeceraDNS=DatosUDP[:12]                       #Obtenemos la cabecera dns
    Consultas=DatosUDP[12:]                         #Obtenemos las consultas dns

    #Desglosamos los datos de la cabecera DNS
    Identificador= hex((CabeceraDNS[0] <<8) | CabeceraDNS[1])
    Flags= hex((CabeceraDNS[2] << 8) | CabeceraDNS[3])
    questions=(CabeceraDNS[4] << 8) | CabeceraDNS[5]
    answers=(CabeceraDNS[6] << 8) | CabeceraDNS[7]

    #Mostramos los datos de la cabecera DNS
    print('\n\t -DNS Message:')
    print('\t\t -ID= ',Identificador)
    print('\t\t -Flags= ',Flags)

     #Comprobamos si es un mensaje de consulta o respuesta
    if (CabeceraDNS[2] >> 1)==0:
        print('\t\t -Message is a Standard query')
    else:
        print('\t\t -Message is a Standard query response')

    print('\t\t -Questions= ',questions)
    print('\t\t -Answers= ',answers)



# receive a package
for i in range(10):
    datos0=s.recvfrom(65535)
    ##print(datos0)
    datos1=datos0[0]
    ##print(datos1)
    DatagramaIP=list(datos1)
    CabeceraIP = DatagramaIP[:20]           #Obtenemos la cabecera IP(20 bytes)
    DatosIP=DatagramaIP[20:]                #El resto son los datos del paquete IP


    #Desglosamos los datos de la cabecera IP
    version=CabeceraIP[0] >> 4              #Obtenemos la versión quie son los 4 primeros bits
    HL= CabeceraIP[0] & 0x0F                #Obtenemos el tamaño de la cabnecera(20 bytes)
    TOS = CabeceraIP[1]                     #
    LongitudTotal = (CabeceraIP[4] <<8) | (CabeceraIP[3])       #Obtenemos la longitud total de el datagrama
    Identificador= (CabeceraIP[4] <<8) | (CabeceraIP[5])        #identificador del paquete IP
    Fragmentacion = (CabeceraIP[6] <<8) | (CabeceraIP[7])
    DF = (Fragmentacion & 0b0100000000000000) != 0
    MF = (Fragmentacion & 0b0010000000000000) != 0
    Offset = Fragmentacion & 0b0001111111111111
    TTL= CabeceraIP[8]                          #Obtenemos el tiempo de vida del paquete
    Protocolo = CabeceraIP[9]                   #Obtenemos el protocolo de la capa superior
    checksum= hex((CabeceraIP[10] << 8) | CabeceraIP[11])        #Obtenemos la suma de verificacion recibida en el paquete


    #Mostramos los campos de la cabecera IP
    print('HOST: ', HOST)
    print('\t -IPv4 PAcket: ')
    print('\t\t -Version: ', version,', ','HL: ', HL*4,'bytes, ','TOS: ', TOS,', ','Longituda Total: ', LongitudTotal)
    print('\t\t -Identificador: ', hex(Identificador),', ','Fragmentacion: ', bin(Fragmentacion),', ','DF: ', DF,', ','MF: ', MF,', ','Offset: ', Offset)
    print('\t\t -TTL: ', TTL,', ','Protocolo: ', Protocolo,', ','Checksum(recibido): ', checksum)

    #El numero del campo protocolo ejecutara la función para mostrar la cabecera de la capa superior
    if DatagramaIP[9]==1:

        cabecera_ICMP(DatosIP)
    elif DatagramaIP[9]==6:

        cabecera_TCP(DatosIP)
    elif DatagramaIP[9] ==17:

        cabecera_UDP(DatosIP)

    #Mostramos todos los datos del paquete
    print('------------------------------------------')
    print('\t\t -DatagramaIP:','\n',DatagramaIP)
    print('\t\t -CabeceraIP:','\n',CabeceraIP)
    print('\t\t -DatosIP:','\n',DatosIP)


# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
