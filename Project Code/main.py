import ftplib
from cryptography.hazmat.primitives.asymmetric import rsa
from Algorithms import*
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
def uploadFileToFtp(localFilePath, ftpHost, ftpPort, ftpUname, ftpPass, remoteWorkingDirectory):
    # initialize the flag that specifies if upload is success
    isUploadSuccess: bool = False

    # extract the filename of local file from the file path
    _, targetFilename = os.path.split(localFilePath)

    # create an FTP client instance, use the timeout parameter for slow connections only
    ftp = ftplib.FTP(timeout=30)

    # connect to the FTP server
    ftp.connect(ftpHost, ftpPort)

    # login to the FTP server
    ftp.login(ftpUname, ftpPass)

    # change current working directory if specified
    if not (remoteWorkingDirectory == None or remoteWorkingDirectory.strip() == ""):
        _ = ftp.cwd(remoteWorkingDirectory)

    # Read file in binary mode
    with open(localFilePath, "rb") as file:
        # upload file to FTP server using storbinary, specify blocksize(bytes) only if higher upload chunksize is required
        retCode = ftp.storbinary(f"STOR {targetFilename}", file, blocksize=1024*1024)

    # send QUIT command to the FTP server and close the connection
    ftp.quit()

    # check if upload is success using the return code (retCode)
    if retCode.startswith('226'):
        isUploadSuccess = True

    # return the upload status
    return isUploadSuccess
def downloadFilesFromFtp(localfolderPath, targetFilenames, ftpHost, ftpPort, ftpUname, ftpPass, remoteWorkingDirectory):
    # initialize the flag that specifies if download is success
    isDownloadSuccess: bool = False

    # create an FTP client instance, use the timeout parameter for slow connections only
    ftp = ftplib.FTP(timeout=30)

    # connect to the FTP server
    ftp.connect(ftpHost, ftpPort)

    # login to the FTP server
    ftp.login(ftpUname, ftpPass)

    # change current working directory if specified
    if not (remoteWorkingDirectory == None or remoteWorkingDirectory.strip() == ""):
        _ = ftp.cwd(remoteWorkingDirectory)

    # iterate through each remote filename and download
    for fItr in range(len(targetFilenames)):
        targetFilename = targetFilenames[fItr]
        # derive the local file path by appending the local folder path with remote filename
        localFilePath = os.path.join(localfolderPath, targetFilename)
        print("downloading file {0}".format(targetFilename))
        # download FTP file using retrbinary function
        with open(localFilePath, "wb") as file:
            retCode = ftp.retrbinary("RETR " + targetFilename, file.write)

    # send QUIT command to the FTP server and close the connection
    ftp.quit()

    # check if download is success using the return code (retCode)
    if retCode.startswith('226'):
        isDownloadSuccess = True
    return isDownloadSuccess
FTP_HOST = "127.0.0.1"
FTP_PORT = 6060
FTP_USER = "username"
FTP_PASS = "P@ssw0rd"
localFolderPath = "FromFTPServer"
# remoteFolder = "Folder1"
remoteFilenames = ["data_enc.txt","encrypted_keys.txt"]


with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    #write_key()
    #key = load_key()
plainfile = "data.txt"
cipherfile="data_enc.txt"
#f = open("keyfile.txt", "w+")
f = open("encrypted_keys.txt", "w+")
keyfile="keyfile.txt"
encrypted_keys="encrypted_keys.txt"
f.close()


from tkinter import *
from tkinter import ttk
win= Tk()
win.geometry("350x350")

def btnAESenc():

    encryptAES(plainfile,cipherfile,keyfile)
    encryptRSA(keyfile, public_key, encrypted_keys)

def btnDESenc():
    encryptDES(plainfile, cipherfile, keyfile)
    encryptRSA(keyfile, public_key, encrypted_keys)

def upload():
    # upload file
    isUploadSuccess = uploadFileToFtp(cipherfile, FTP_HOST, FTP_PORT, FTP_USER, FTP_PASS, None)
    isUploadSuccess = uploadFileToFtp(encrypted_keys, FTP_HOST, FTP_PORT, FTP_USER, FTP_PASS, None)
    print("upload status = {0}".format(isUploadSuccess))

def download():
    # Download file
    isDownloadSuccess = downloadFilesFromFtp(
        localFolderPath, remoteFilenames, FTP_HOST, FTP_PORT, FTP_USER, FTP_PASS, None)
    print("download status = {0}".format(isDownloadSuccess))

def btnAESdec():
    encrypted_keys = "FromFTPServer/encrypted_keys.txt"
    recovered_keys = "FromFTPServer/recovered_keys.txt"
    cipherfile = "FromFTPServer/data_enc.txt"
    f = open("FromFTPServer/data_dec.txt", "w+")
    plainfile = "FromFTPServer/data_dec.txt"

    decryptRSA(encrypted_keys, private_key, recovered_keys)
    decryptAES(cipherfile,plainfile, recovered_keys)
    f.close()

def btnDESdec():
    encrypted_keys = "FromFTPServer/encrypted_keys.txt"
    recovered_keys = "FromFTPServer/recovered_keys.txt"
    cipherfile = "FromFTPServer/data_enc.txt"
    f = open("FromFTPServer/data_dec.txt", "w+")
    plainfile = "FromFTPServer/data_dec.txt"

    decryptRSA(encrypted_keys, private_key, recovered_keys)
    decryptDES(cipherfile, plainfile, recovered_keys)
    f.close()

ttk.Label(text="Run Each Algorithm with its Buttons alone").place(x=50,y=175)

btn1=ttk.Button(win, text="Encrypt With DES", command=btnDESenc)
btn2=ttk.Button(win, text="Upload", command=upload)
btn3=ttk.Button(win, text="Download", command=download)
btn4=ttk.Button(win, text="Decrypt With DES", command=btnDESdec)

btn1.place(x=25,y=25)
btn2.place(x=25,y=50)
btn3.place(x=25,y=75)
btn4.place(x=25,y=100)

btn5=ttk.Button(win, text="Encrypt with AES", command=btnAESenc)
btn6=ttk.Button(win, text="Upload", command=upload)
btn7=ttk.Button(win, text="Download", command=download)
btn8=ttk.Button(win, text="Decrypt With AES", command=btnAESdec)

btn5.place(x=200,y=25)
btn6.place(x=200,y=50)
btn7.place(x=200,y=75)
btn8.place(x=200,y=100)
win.mainloop()

