#!/usr/bin/env python

#autor: Vojtech Jurka (xjurka08)



import sys

import socket



def getFunction(data):



    buff = data.split('=', 1)[0]

    

    if buff != "/resolve?name":

        return "HTTP/1.1 400 Bad Request\r\n\r\n"



    data = data.split('=', 1)[1]



    addr = data.split('&', 1)[0]

    data = data.split('&', 1)[1]

    

    if data == "type=A HTTP/1.1\r":

        

        try:

            out = socket.gethostbyname(addr)

        except socket.gaierror:

            return "HTTP/1.1 404 Not Found\r\n\r\n"

        

        out = "HTTP/1.1 200 OK\r\n\r\n"+addr+":A="+out+"\n"

    

    elif data == "type=PTR HTTP/1.1\r":

        try:

            out = socket.gethostbyaddr(addr)

        except socket.gaierror:

            return "HTTP/1.1 404 Not Found\r\n\r\n"

        out = out[0]

        out = "HTTP/1.1 200 OK\r\n\r\n"+addr+":PTR="+out+"\n"



    else:

        

        return "HTTP/1.1 400 Bad Request\r\n\r\n"





    return(out)





def postFunction(data):

    buff = data.split('\n', 1)[0]



    if buff != "/dns-query HTTP/1.1\r":

        return "HTTP/1.1 400 Bad Request\r\n\r\n"



    data = data.split('\n', 1)[1]

    data = data.split('\n')

    outdata = []



    for i in range(len(data)):



        arr = data[i].split() #zbavim se mezer

        buff = ""

        buff = buff.join(arr)



        buff = buff.split(':')



        if len(buff) != 2:

            continue

        

        if buff[1] == "A":

            try:

                out = socket.gethostbyname(buff[0])

            except socket.gaierror:

                continue

        

            outdata.append(buff[0]+":A="+out)



        elif buff[1] == "PTR":

            try:

                out = socket.gethostbyaddr(buff[0])

            except socket.gaierror:

                continue

            

            out = out[0]

            outdata.append(buff[0]+":PTR="+out)

        else:

            pass

    

    if len(data) == 0:

        return "HTTP/1.1 404 Not Found\r\n\r\n"

    else:

        out = "\n"

        out = out.join(outdata)

        out = "HTTP/1.1 200 OK\r\n\r\n"+out+"\n"

    

    return(out)





HOST = '127.0.0.1'

PORT = int(sys.argv[1])





with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.bind((HOST, PORT))

    s.listen()

    while True:

        conn, addr = s.accept()

        data = conn.recv(1024)



        if not data:

            break

        

        data = data.decode()

        

        first_word = data.split('\n')[0]



        first_word = data.split(' ', 1)[0]

        data = data.split(' ', 1)[1]

        

        if first_word == "GET":

            data = data.split('\n')[0]

            output = getFunction(data)

        elif first_word == "POST":

            output = postFunction(data)

        else:

            output = "HTTP/1.1 405 Method Not Allowed\r\n\r\n"



        conn.sendall(output.encode())

        conn.close()
        