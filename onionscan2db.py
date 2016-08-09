#!/usr/bin/python

import argparse
import json
import os
import sqlite3
import sys

def isSQLite3(filename):
    if not os.path.isfile(filename):
        return False
    if os.path.getsize(filename) < 100: # SQLite database file header is 100 bytes
        return False

    with open(filename, 'rb') as fd:
        header = fd.read(100)

    return header[:16] == 'SQLite format 3\x00'

def buildDatabase(filename):
    try:
        print "[*] Building new database: %s" % filename
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.executescript("""BEGIN TRANSACTION;
        CREATE TABLE open_directories (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, directory TEXT NOT NULL);
        CREATE TABLE web_findings (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, server_powered_by TEXT, server_version TEXT, found_apache_mod_status INTEGER, snapshot TEXT, page_title TEXT);
        CREATE TABLE response_headers (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, header_name TEXT, header_value TEXT);
        CREATE TABLE page_referenced_directories (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, directory TEXT NOT NULL);
        CREATE TABLE smtp_findings (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, smtp_fingerprint TEXT, smtp_banner TEXT);
        CREATE TABLE ssh_findings (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, ssh_key TEXT NOT NULL);
        CREATE TABLE pgp_keys (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, armored_key TEXT, identity TEXT, fingerprint TEXT);
        CREATE TABLE onions (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, hidden_service TEXT UNIQUE NOT NULL, web_detected INTEGER, ssh_detected INTEGER, ricochet_detected INTEGER, irc_detected INTEGER, ftp_detected INTEGER, smtp_detected INTEGER, bitcoin_detected INTEGER, mongodb_detected INTEGER, vnc_detected INTEGER, xmpp_detected INTEGER);
        CREATE TABLE bitcoin_findings (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, bitcoin_address TEXT NOT NULL);
        CREATE TABLE exif_images (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, location TEXT NOT NULL);
        CREATE TABLE exif_data (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, exif_image_id INTEGER NOT NULL, tag_name TEXT, tag_value TEXT);
        CREATE TABLE linked_sites (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, address TEXT NOT NULL);
        CREATE TABLE ftp_findings (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, ftp_fingerprint TEXT, ftp_banner TEXT);
        CREATE TABLE internal_pages (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, page TEXT NOT NULL);
        CREATE TABLE related_onion_services (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, service TEXT NOT NULL);
        CREATE TABLE related_onion_domains (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, domain TEXT NOT NULL);
        CREATE TABLE ip_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, address TEXT NOT NULL);
        CREATE TABLE hashes (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, hash TEXT NOT NULL);
        CREATE TABLE interesting_files (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, onion_id INTEGER NOT NULL, file TEXT NOT NULL);
        COMMIT TRANSACTION;""")
    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertNewOnion(database, data):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO onions (hidden_service,web_detected,ssh_detected,
        ricochet_detected,irc_detected,ftp_detected,smtp_detected,bitcoin_detected,
        mongodb_detected,vnc_detected,xmpp_detected) VALUES (?,?,?,?,?,?,?,?,?,?,?)"""
        cursor.execute(sql, (data["hiddenService"],data["webDetected"],
            data["sshDetected"],data["ricochetDetected"],data["ircDetected"],
            data["ftpDetected"],data["smtpDetected"],data["bitcoinDetected"],
            data["mongodbDetected"],data["vncDetected"],data["xmppDetected"]))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertWebData(database, onion_id, data):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO web_findings (onion_id,server_powered_by,
        server_version,found_apache_mod_status,snapshot,page_title) VALUES (?,?,?,?,?,?)"""
        cursor.execute(sql, (onion_id,data["serverPoweredBy"],
            data["serverVersion"],data["foundApacheModStatus"],data["snapshot"],
            data["pageTitle"]))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertSSHData(database, onion_id, ssh_key):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO ssh_findings (onion_id,ssh_key) VALUES (?,?)"""
        cursor.execute(sql, (onion_id,ssh_key))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertFTPData(database, onion_id, data):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO ftp_findings (onion_id,ftp_fingerprint,ftp_banner)
            VALUES (?,?,?)"""
        cursor.execute(sql, (onion_id,data["ftpFingerprint"],data["ftpBanner"]))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertSMTPData(database, onion_id, data):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO smtp_findings (onion_id,smtp_fingerprint,smtp_banner)
            VALUES (?,?,?)"""
        cursor.execute(sql, (onion_id,data["smtpFingerprint"],data["smtpBanner"]))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertLinkedSite(database, onion_id, site):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO linked_sites (onion_id,address) VALUES (?,?)"
        cursor.execute(sql, (onion_id,site))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertIPAddress(database, onion_id, address):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO ip_addresses (onion_id,address) VALUES (?,?)"
        cursor.execute(sql, (onion_id,address))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertBitcoinAddress(database, onion_id, address):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO bitcoin_findings (onion_id,bitcoin_address) VALUES (?,?)"
        cursor.execute(sql, (onion_id,address))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertPGPKey(database, onion_id, pgpData):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO pgp_keys (onion_id,armored_key,identity,fingerprint)
            VALUES (?,?,?,?)"""
        cursor.execute(sql, (onion_id,pgpData["armoredKey"],pgpData["identity"],pgpData["fingerprint"]))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertPRD(database, onion_id, directory):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO page_referenced_directories (onion_id,directory)
            VALUES (?,?)"""
        cursor.execute(sql, (onion_id,directory))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertHash(database, onion_id, hash):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO hashes (onion_id,hash) VALUES (?,?)"
        cursor.execute(sql, (onion_id,hash))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertInterestingFile(database, onion_id, file):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO interesting_files (onion_id,file) VALUES (?,?)"
        cursor.execute(sql, (onion_id,file))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertInternalPage(database, onion_id, page):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO internal_pages (onion_id,page) VALUES (?,?)"
        cursor.execute(sql, (onion_id,page))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertRelatedOnionService(database, onion_id, service):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO related_onion_services (onion_id,service) VALUES (?,?)"
        cursor.execute(sql, (onion_id,service))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertRelatedOnionDomain(database, onion_id, domain):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO related_onion_domains (onion_id,domain) VALUES (?,?)"
        cursor.execute(sql, (onion_id,domain))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertOpenDirectory(database, onion_id, directory):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO open_directories (onion_id,directory) VALUES (?,?)"
        cursor.execute(sql, (onion_id,directory))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertResponseHeader(database, onion_id, header_name, header_value):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = """INSERT INTO response_headers (onion_id,header_name,
            header_value) VALUES (?,?,?)"""
        cursor.execute(sql, (onion_id,header_name,header_value))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertExifImage(database, onion_id, location):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO exif_images (onion_id,location) VALUES (?,?)"
        cursor.execute(sql, (onion_id,location))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def insertExifData(database, exif_image_id, tag_name, tag_value):
    try:
        #print "[*] Opening database: %s" % database
        db = sqlite3.connect(database)
        cursor = db.cursor()

        sql = "INSERT INTO exif_data (exif_image_id,tag_name,tag_value) VALUES (?,?,?)"
        cursor.execute(sql, (exif_image_id,tag_name,tag_value))
        db.commit()

        sql = "SELECT last_insert_rowid()"
        return cursor.execute(sql).fetchone()[0]

    except sqlite3.Error, e:
        if e.args == 2:
            print "[!] Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        else:
            print "[!] Error: %s" % e
            sys.exit(1)
    finally:
        db.close()

def processOnionscan(database,json_file):
    with open(json_file, "r") as file:
        data = json.load(file)
    onion_id = insertNewOnion(database_file, data)
    if data["webDetected"]:
        insertWebData(database_file, onion_id, data)
    if data["sshDetected"]:
        insertSSHData(database_file, onion_id, data["sshKey"])
    if data["ftpDetected"]:
        insertFTPData(database_file, onion_id, data)
    if data["smtpDetected"]:
        insertFTPData(database_file, onion_id, data)
    if data["linkedSites"]:
        for site in data["linkedSites"]:
            insertLinkedSite(database_file, onion_id, site)
    if data["ipAddresses"]:
        for address in data["ipAddresses"]:
            insertIPAddress(database_file, onion_id, address)
    if data["bitcoinAddresses"]:
        for address in data["bitcoinAddresses"]:
            insertIPAddress(database_file, onion_id, address)
    if data["pgpKeys"]:
        for pgpData in data["pgpKeys"]:
            insertPGPKey(database_file, onion_id, pgpData)
    if data["pageReferencedDirectories"]:
        for directory in data["pageReferencedDirectories"]:
            insertPRD(database_file, onion_id, directory)
    if data["hashes"]:
        for hash in data["hashes"]:
            insertHash(database_file, onion_id, hash)
    if data["interestingFiles"]:
        for file in data["interestingFiles"]:
            insertInterestingFile(database_file, onion_id, file)
    if data["internalPages"]:
        for page in data["internalPages"]:
            insertInternalPage(database_file, onion_id, page)
    if data["relatedOnionServices"]:
        for service in data["relatedOnionServices"]:
            insertRelatedOnionService(database_file, onion_id, service)
    if data["relatedOnionDomains"]:
        for domain in data["relatedOnionDomains"]:
            insertRelatedOnionDomain(database_file, onion_id, domain)
    if data["openDirectories"]:
        for directory in data["openDirectories"]:
            insertOpenDirectory(database_file, onion_id, directory)
    if data["responseHeaders"]:
        for header in data["responseHeaders"]:
            insertResponseHeader(database_file, onion_id, header, data["responseHeaders"][header])
    if data["exifImages"]:
        for image in data["exifImages"]:
            image_id = insertExifImage(database_file, onion_id, image["location"])
            for tag in image["exifTags"]:
                insertExifData(database_file, image_id, tag["name"], tag["value"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="parses JSON formatted OnionScan results from a specified directory into a SQLite database")
    parser.add_argument("-d", "--directory", help="directory containing Onionscan JSON results", nargs=1, required=True)
    parser.add_argument("-o", "--output", help="output SQLite database file", nargs=1, required=True)
    args = parser.parse_args()

    database_file = args.output[0]
    result_dir = args.directory[0]

    if isSQLite3(database_file):
        print "[!] Database already exists... exiting"
        sys.exit(1)

    count = 1
    json_files = []

    for file in os.listdir(result_dir):
        if file.endswith(".json"):
            json_files.append(os.path.join(result_dir,file))
    if not len(json_files):
        print "[!] No JSON files found... exiting"
        sys.exit(1)

    buildDatabase(database_file)
    for file in json_files:
        print "[+] Processing file %d of %d" % (count,len(json_files))
        processOnionscan(database_file,file)
        count += 1
