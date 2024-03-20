# DLNAmpvRenderer v1.3.1 (https://github.com/PCigales/DLNAmpvRenderer)
# Copyright © 2022 PCigales
# This program is licensed under the GNU GPLv3 copyleft license (see https://www.gnu.org/licenses)

import threading
import msvcrt
import ctypes, ctypes.wintypes
import os
from functools import partial
import socket
import socketserver
import selectors
import urllib.parse, urllib.request, urllib.error
import ssl
import struct
import email.utils
from xml.dom import minidom
import time
import uuid
import subprocess
import json
import html
from io import BytesIO
import locale
import argparse


NAME = 'DLNAmpvRenderer'
UDN = 'uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'DLNAmpvRenderer'))


FR_STRINGS = {
  'license': 'Ce programme est sous licence copyleft GNU GPLv3 (voir https://www.gnu.org/licenses)',
  'help': 'affichage du message d\'aide et interruption du script', 
  'parser_ip': 'adresse IP du renderer [auto-sélectionnée par défaut - "0.0.0.0", soit toutes les interfaces, si option présente sans mention d\'adresse]',
  'parser_port': 'port TCP du renderer [8000 par défaut]',
  'parser_name': 'nom du renderer [DLNAmpvRenderer par défaut]',
  'parser_minimized': 'passage en mode minimisé quand inactif [désactivé par défaut]',
  'parser_fullscreen': 'passage en mode plein écran à chaque session [désactivé par défaut]',
  'parser_mkv': 'masque la prise en charge du format matroska à WMPDMC pour permettre le contrôle distant [désactivé par défaut]',
  'parser_trust': 'désactive la vérification des adresses avant leur transmission à mpv [désactivé par défaut]',
  'parser_subtitles': 'active la recherche systématique de sous-titres [désactivé par défaut]',
  'parser_gapless': 'active la lecture sans blanc (sous réserve de compatibilité avec le contrôleur), avec préchargement audio (pourrait faire dysfonctionner mpv) si "p" mentionné [désactivé par défaut]',
  'parser_verbosity': 'niveau de verbosité de 0 à 2 [0 par défaut]',
  'keyboard_s': 'Appuyez sur "S" ou fermez mpv pour quitter',
  'enabled': 'activé',
  'disabled': 'désactivé',
  'keyboard_m': 'Appuyez sur "M" pour activer/désactiver le passage en mode minimisé quand inactif - mode actuel: %s',
  'keyboard_f': 'Appuyez sur "F" pour activer/désactiver le passage en mode plein écran à chaque session - mode actuel: %s',
  'mode_m': 'Passage en mode minimisé quand inactif: %s',
  'mode_f': 'Passage en mode plein écran à chaque session: %s',
  'player_failure': 'Lecteur - échec du lancement',
  'ip_failure': 'Échec de la récupération de l\'addresse ip de l\'hôte',
  'request_failure': 'Échec du démarrage de l\'écoute des requêtes à l\'adresse %s:%s',
  'current_content': 'Contenu en cours: %s | %s | %s',
  'next_content': 'Prochain contenu: %s | %s | %s …',
  'next_current': '… en cours',
  'video': 'vidéo',
  'audio': 'audio',
  'image': 'image'
}
EN_STRINGS = {
  'license': 'This program is licensed under the GNU GPLv3 copyleft license (see https://www.gnu.org/licenses)',
  'help': 'display of the help message and interruption of the script',
  'parser_ip': 'IP address of the renderer [auto-selected by default - "0.0.0.0", meaning all interfaces, if option present with no address mention]',
  'parser_port': 'TCP port of the renderer [8000 by default]',
  'parser_name': 'name of the renderer [DLNAmpvRenderer by default]',
  'parser_minimized': 'switching to minimized mode when idle [disabled by default]',
  'parser_fullscreen': 'switching to fullscreen mode at each session [disabled by default]',
  'parser_mkv': 'mask support of matroska format to WMPDMC to allow the remote control [disabled by default]',
  'parser_trust': 'disable the checking of the addresses before their transmission to mpv [disabled by default]',
  'parser_subtitles': 'enable systematic search for subtitles [disabled by default]',
  'parser_gapless': 'enable gapless playback (subject to controller compatibility), with audio prefetch (might make mpv malfunction) if "p" mentioned [disabled by default]',
  'parser_verbosity': 'level of verbosity from 0 to 2 [0 by default]',
  'keyboard_s': 'Press "S" or close mpv to exit',
  'enabled': 'enabled',
  'disabled': 'disabled',
  'keyboard_m': 'Press "M" to toggle the switching to minimized mode when idle - current mode: %s',
  'keyboard_f': 'Press "F" to toggle the switching to fullscreen mode at each session - current mode: %s',
  'mode_m': 'Switching to minimized mode when idle: %s',
  'mode_f': 'Switching to fullscreen mode at each session: %s',
  'player_failure': 'Player - launch failure',
  'ip_failure': 'Failure of the retrieval of the host ip address',
  'request_failure': 'Failure of the startup of the listening of requests at the address %s:%s',
  'current_content': 'Current content: %s | %s | %s',
  'next_content': 'Next content: %s | %s | %s …',
  'next_current': '… current',
  'video': 'video',
  'audio': 'audio',
  'image': 'image'
}

locale.setlocale(locale.LC_TIME, '')
LSTRINGS = EN_STRINGS
try:
  if locale.getlocale()[0][:2].lower() == 'fr':
    LSTRINGS = FR_STRINGS
except:
  pass


class log_event:

  def __init__(self, verbosity):
    self.verbosity = verbosity

  def log(self, msg, level):
    if level <= self.verbosity:
      print(time.strftime('%x %X', time.localtime()), ':', msg)


def _open_url(url, method=None, timeout=None, test_range=False):
  header = {'User-Agent': 'Lavf'}
  if method and test_range:
    if method.upper() == 'HEAD':
      header['Range'] = 'bytes=0-'
  req = urllib.request.Request(url, headers=header, method=method)
  rep = None
  try:
    rep = urllib.request.urlopen(req, data=None, timeout=timeout)
  except urllib.error.HTTPError as e:
    if e.code == 406 and test_range and (method or '').upper() == 'HEAD':
      del header['Range']
      req = urllib.request.Request(url, headers=header, method=method)
      rep = None
      try:
        rep = urllib.request.urlopen(req, data=None, timeout=timeout)
      except:
        pass
  except:
    pass
  return rep

def _XMLGetNodeText(node):
  text = []
  for childNode in node.childNodes:
    if childNode.nodeType == node.TEXT_NODE:
      text.append(childNode.data)
  return(''.join(text))


class HTTPExplodedMessage():

  __slots__ = ('method', 'path', 'version', 'code', 'message', 'headers', 'body', 'expect_close')

  def __init__(self):
    self.method = self.path = self.version = self.code = self.message = self.body = self.expect_close = None
    self.headers = {}

  def __bool__(self):
    return self.method is not None or self.code is not None

  def clear(self):
    self.__init__()
    return self

  def header(self, name, default=None):
    return self.headers.get(name.title(), default)

  def in_header(self, name, value):
    h = self.header(name)
    return False if h is None else (value.lower() in map(str.strip, h.lower().split(',')))

  def __repr__(self):
    if self:
      try:
        return '\r\n'.join(('<HTTPExplodedMessage at %#x>\r\n----------' % id(self), (' '.join(filter(None, (self.method, self.path, self.version, self.code, self.message)))), *map(': '.join, self.headers.items()), '----------\r\nLength of body: %s byte(s)' % len(self.body or ''), '----------\r\nClose expected: %s' % self.expect_close))
      except:
        return '<HTTPExplodedMessage at %#x>\r\n<corrupted object>' % id(self)
    else:
      return '<HTTPExplodedMessage at %#x>\r\n<no message>' % id(self)


class HTTPMessage():

  @staticmethod
  def _read_headers(msg, http_message):
    if not msg:
      return False
    a = None
    for msg_line in msg.replace('\r\n', '\n').split('\n')[:-2]:
      if a is None:
        try:
          a, b, c = msg_line.strip().split(None, 2)
        except:
          try:
            a, b, c = *msg_line.strip().split(None, 2), ''
          except:
            return False
      else:
        try:
          header_name, header_value = msg_line.split(':', 1)
        except:
          return False
        header_name = header_name.strip().title()
        if header_name:
          header_value = header_value.strip()
          if not header_name in ('Content-Length', 'Location', 'Host') and http_message.headers.get(header_name):
            if header_value:
              http_message.headers[header_name] += ', ' + header_value
          else:
            http_message.headers[header_name] = header_value
        else:
          return False
    if a is None:
      return False
    if a[:4].upper() == 'HTTP':
      http_message.version = a.upper()
      http_message.code = b
      http_message.message = c
    else:
      http_message.method = a.upper()
      http_message.path = b
      http_message.version = c.upper()
    http_message.expect_close = http_message.in_header('Connection', 'close') or (http_message.version.upper() != 'HTTP/1.1' and not http_message.in_header('Connection', 'keep-alive'))
    return True

  def __new__(cls, message=None, body=True, decode='utf-8', timeout=5, max_length=1048576, max_hlength=1048576):
    http_message = HTTPExplodedMessage()
    if message is None:
      return http_message
    max_hlength = min(max_length, max_hlength)
    rem_length = max_hlength
    iss = isinstance(message, socket.socket)
    if not iss:
      msg = message[0]
    else:
      message.settimeout(timeout)
      msg = b''
    while True:
      msg = msg.lstrip(b'\r\n')
      if msg and msg[0] < 0x20:
        return http_message
      body_pos = msg.find(b'\r\n\r\n')
      if body_pos >= 0:
        body_pos += 4
        break
      body_pos = msg.find(b'\n\n')
      if body_pos >= 0:
        body_pos += 2
        break
      if not iss or rem_length <= 0:
        return http_message
      try:
        bloc = message.recv(min(rem_length, 1048576))
        if not bloc:
          return http_message
      except:
        return http_message
      rem_length -= len(bloc)
      msg = msg + bloc
    if not cls._read_headers(msg[:body_pos].decode('ISO-8859-1'), http_message):
      return http_message.clear()
    if not iss:
      http_message.expect_close = True
    if http_message.code in ('100', '101', '204', '304'):
      http_message.body = b''
      return http_message
    if not body:
      http_message.body = msg[body_pos:]
      return http_message
    rem_length += max_length - max_hlength
    chunked = http_message.in_header('Transfer-Encoding', 'chunked')
    if chunked:
      body_len = -1
    else:
      body_len = http_message.header('Content-Length')
      if body_len is None:
        if not iss or (http_message.code in ('200', '206') and http_message.expect_close):
          body_len = -1
        else:
          body_len = 0
      else:
        try:
          body_len = max(0, int(body_len))
        except:
          return http_message.clear()
    if http_message.in_header('Expect', '100-continue') and iss:
      if body_pos + body_len - len(msg) <= rem_length:
        try:
          message.sendall('HTTP/1.1 100 Continue\r\n\r\n'.encode('ISO-8859-1'))
        except:
          return http_message.clear()
      else:
        try:
          message.sendall(('HTTP/1.1 413 Payload too large\r\nContent-Length: 0\r\nDate: %s\r\nCache-Control: no-cache, no-store, must-revalidate\r\n\r\n' % email.utils.formatdate(time.time(), usegmt=True)).encode('ISO-8859-1'))
        except:
          pass
        return http_message.clear()
    if not chunked:
      if body_len < 0:
        if not iss:
          http_message.body = msg[body_pos:]
        else:
          bbuf = BytesIO()
          rem_length -= bbuf.write(msg[body_pos:])
          while rem_length > 0:
            try:
              bw = bbuf.write(message.recv(min(rem_length, 1048576)))
              if not bw:
                break
              rem_length -= bw
            except:
              return http_message.clear()
          if rem_length <= 0:
            return http_message.clear()
          http_message.body = bbuf.getvalue()
      elif len(msg) < body_pos + body_len:
        if not iss or body_pos + body_len - len(msg) > rem_length:
          return http_message.clear()
        bbuf = BytesIO()
        body_len -= bbuf.write(msg[body_pos:])
        while body_len:
          try:
            bw = bbuf.write(message.recv(min(body_len, 1048576)))
            if not bw:
              return http_message.clear()
            body_len -= bw
          except:
            return http_message.clear()
        http_message.body = bbuf.getvalue()
      else:
        http_message.body = msg[body_pos:body_pos+body_len]
    else:
      bbuf = BytesIO()
      buff = msg[body_pos:]
      while True:
        chunk_pos = -1
        rem_slength = max_hlength - len(buff)
        while chunk_pos < 0:
          buff = buff.lstrip(b'\r\n')
          chunk_pos = buff.find(b'\r\n')
          if chunk_pos >= 0:
            chunk_pos += 2
            break
          chunk_pos = buff.find(b'\n')
          if chunk_pos >= 0:
            chunk_pos += 1
            break
          if not iss or rem_slength <= 0 or rem_length <= 0:
            return http_message.clear()
          try:
            bloc = message.recv(min(rem_length, rem_slength, 1048576))
            if not bloc:
              return http_message.clear()
          except:
            return http_message.clear()
          rem_length -= len(bloc)
          rem_slength -= len(bloc)
          buff = buff + bloc
        try:
          chunk_len = int(buff[:chunk_pos].split(b';', 1)[0].rstrip(b'\r\n'), 16)
          if not chunk_len:
            break
        except:
          return http_message.clear()
        if chunk_pos + chunk_len - len(buff) > rem_length:
          return http_message.clear()
        if len(buff) < chunk_pos + chunk_len:
          if not iss:
            return http_message.clear()
          chunk_len -= bbuf.write(buff[chunk_pos:])
          while chunk_len:
            try:
              bw = bbuf.write(message.recv(min(chunk_len, 1048576)))
              if not bw:
                return http_message.clear()
              chunk_len -= bw
            except:
              return http_message.clear()
            rem_length -= bw
          buff = b''
        else:
          bbuf.write(buff[chunk_pos:chunk_pos+chunk_len])
          buff = buff[chunk_pos+chunk_len:]
      http_message.body = bbuf.getvalue()
      rem_length = min(rem_length, max_hlength - body_pos - len(buff) + chunk_pos)
      while not (b'\r\n\r\n' in buff or b'\n\n' in buff):
        if not iss or rem_length <= 0:
          return http_message.clear()
        try:
          bloc = message.recv(min(rem_length, 1048576))
          if not bloc:
            return http_message.clear()
        except:
          return http_message.clear()
        rem_length -= len(bloc)
        buff = buff + bloc
    if http_message.body:
      try:
        if decode:
          http_message.body = http_message.body.decode(decode)
      except:
        return http_message.clear()
    return http_message


class HTTPRequest():

  SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  SSLContext.check_hostname = False
  SSLContext.verify_mode = ssl.CERT_NONE
  RequestPattern = \
    '%s %s HTTP/1.1\r\n' \
    'Host: %s\r\n%s' \
    '\r\n'

  def __new__(cls, url, method=None, headers=None, data=None, timeout=30, max_length=1073741824, max_hlength=1048576, pconnection=None, ip=''):
    if url is None:
      return HTTPMessage()
    if method is None:
      method = 'GET' if data is None else 'POST'
    redir = 0
    try:
      url_p = urllib.parse.urlsplit(url, allow_fragments=False)
      if headers is None:
        headers = {}
      hitems = headers.items()
      if pconnection is None:
        pconnection = [None]
        hccl = True
      else:
        hccl = 'close' in (e.strip() for k, v in hitems if k.lower() == 'connection' for e in v.lower().split(','))
      headers = {k: v for k, v in hitems if not k.lower() in ('host', 'content-length', 'connection', 'expect')}
      if not 'accept-encoding' in (k.lower() for k, v in hitems):
        headers['Accept-Encoding'] = 'identity'
      if data is not None:
        if not 'chunked' in (e.strip() for k, v in hitems if k.lower() == 'transfer-encoding' for e in v.lower().split(',')):
          headers['Content-Length'] = str(len(data))
      headers['Connection'] = 'close' if hccl else 'keep-alive'
    except:
      return HTTPMessage()
    while True:
      try:
        if pconnection[0] is None:
          if url_p.scheme.lower() == 'http':
            pconnection[0] = socket.create_connection((url_p.hostname, url_p.port if url_p.port is not None else 80), timeout=timeout, source_address=(ip, 0))
          elif url_p.scheme.lower() == 'https':
            n, s, p = url_p.netloc.rpartition(':')
            if s != ':' or ']' in p:
              n = url_p.netloc
            pconnection[0] = cls.SSLContext.wrap_socket(socket.create_connection((url_p.hostname, url_p.port if url_p.port is not None else 443), timeout=timeout, source_address=(ip, 0)), server_side=False, server_hostname=n)
          else:
            raise
        else:
          try:
            pconnection[0].settimeout(timeout)
          except:
            pass
        msg = cls.RequestPattern % (method, (url_p.path + ('?' + url_p.query if url_p.query else '')).replace(' ', '%20') or '/', url_p.netloc, ''.join(k + ': ' + v + '\r\n' for k, v in headers.items()))
        pconnection[0].sendall(msg.encode('iso-8859-1') + (data or b''))
        code = '100'
        while code == '100':
          resp = HTTPMessage(pconnection[0], body=(method.upper() != 'HEAD'), decode=None, timeout=timeout, max_length=max_length, max_hlength=max_hlength)
          code = resp.code
          if code == '100':
            redir += 1
            if redir > 5:
              raise
        if code is None:
          raise
        if code[:2] == '30' and code != '304':
          if resp.header('location'):
            url = urllib.parse.urljoin(url, resp.header('location'))
            urlo_p = url_p
            url_p = urllib.parse.urlsplit(url, allow_fragments=False)
            if headers['Connection'] == 'close' or resp.expect_close or (urlo_p.scheme != url_p.scheme or urlo_p.netloc != url_p.netloc):
              try:
                pconnection[0].close()
              except:
                pass
              pconnection[0] = None
              headers['Connection'] = 'close'
            redir += 1
            if redir > 5:
              raise
            if code == '303':
              if method.upper() != 'HEAD':
                method = 'GET'
              data = None
              for k in list(headers.keys()):
                if k.lower() in ('transfer-encoding', 'content-length', 'content-type'):
                  del headers[k]
          else:
            raise
        else:
          break
      except:
        try:
          pconnection[0].close()
        except:
          pass
        pconnection[0] = None
        return HTTPMessage()
    if headers['Connection'] == 'close' or resp.expect_close:
      try:
        pconnection[0].close()
      except:
        pass
      pconnection[0] = None
    return resp


ULONG = ctypes.wintypes.ULONG
ULONG_PTR = ctypes.c_uint64
DWORD = ctypes.wintypes.DWORD
USHORT = ctypes.wintypes.USHORT
BOOL = ctypes.c_bool
PVOID = ctypes.c_void_p
HANDLE = ctypes.wintypes.HANDLE
POINTER = ctypes.POINTER
pointer = ctypes.pointer
LPWSTR = ctypes.wintypes.LPWSTR
WINFUNCTYPE = ctypes.WINFUNCTYPE
kernel32 = ctypes.WinDLL('kernel32',  use_last_error=True)

class OVERLAPPED_STRUCT(ctypes.Structure):
  _fields_ = [('Offset', DWORD),('OffsetHigh', DWORD)]

class OVERLAPPED_UNION(ctypes.Union):
  _anonymous_ = ('u', )
  _fields_ = [('u', OVERLAPPED_STRUCT), ('Pointer', PVOID)]

class OVERLAPPED(ctypes.Structure):
  _anonymous_ = ('u', )
  _fields_ = [('Internal', ULONG_PTR), ('InternalHigh', ULONG_PTR), ('u', OVERLAPPED_UNION), ('hEvent', HANDLE)]

LPOVERLAPPED = POINTER(OVERLAPPED)
LPOVERLAPPED_COMPLETION_ROUTINE = WINFUNCTYPE(None, DWORD, DWORD, LPOVERLAPPED)

class IPCmpvControler(threading.Thread):

  SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

  def _Py_ReadFileEx_Completion_Routine(dwErrorCode, dwNumberOfBytesTransfered, lpOverlapped):
    kernel32.SetEvent(lpOverlapped.contents.hEvent)

  def _Py_WriteFileEx_Completion_Routine(dwErrorCode, dwNumberOfBytesTransfered, lpOverlapped):
    kernel32.SetEvent(lpOverlapped.contents.hEvent)

  ReadFileEx_Completion_Routine = LPOVERLAPPED_COMPLETION_ROUTINE(_Py_ReadFileEx_Completion_Routine)
  WriteFileEx_Completion_Routine = LPOVERLAPPED_COMPLETION_ROUTINE(_Py_WriteFileEx_Completion_Routine)

  def __init__(self, title_name = 'mpv', verbosity=0):
    self.verbosity = verbosity
    self.logger = log_event(verbosity)
    self.title_name = title_name
    threading.Thread.__init__(self)
    self.lpOverlapped_r = pointer(OVERLAPPED())
    self.lpOverlapped_w = pointer(OVERLAPPED())
    self.lpOverlapped_r.contents.hEvent=HANDLE(kernel32.CreateEventW(PVOID(0), BOOL(1), BOOL(0), LPWSTR(urllib.parse.quote(self.title_name, safe='') + '_read')))
    self.lpOverlapped_w.contents.hEvent=HANDLE(kernel32.CreateEventW(PVOID(0), BOOL(1), BOOL(0), LPWSTR(urllib.parse.quote(self.title_name, safe='') + '_write')))
    self.NumberOfBytesTransferred_r = DWORD()
    self.NumberOfBytesTransferred_w = DWORD()
    self.Pipe_handle = None
    self.Pipe_buffer = ctypes.create_string_buffer(10000)
    self.Cmd_Event = HANDLE(kernel32.CreateEventW(PVOID(0), BOOL(1), BOOL(0), LPWSTR(urllib.parse.quote(self.title_name, safe='') + '_input')))
    self.Msg_event = threading.Event()
    self.Cmd_buffer = ["run", ('set_property', 'script-opts', 'osc-visibility=never'), ('observe_property', 1, 'time-pos'), ('observe_property', 2, 'pause'), ('observe_property', 3, 'duration'), ('observe_property', 4, 'mute'), ('observe_property', 5, 'volume'), ('observe_property', 6, 'playlist-playing-pos'), ('observe_property', 7, 'idle-active'), ('set_property', 'title', '${?media-title:${media-title}}${!media-title:No file} - %s' % title_name)]
    self.Msg_buffer = ['run']
    self.Read_pending = False
    kernel32.ResetEvent(self.lpOverlapped_r.contents.hEvent)
    self.Write_pending = False
    kernel32.ResetEvent(self.lpOverlapped_w.contents.hEvent)
    kernel32.ResetEvent(self.Cmd_Event)
    self.Player_events = []
    self.Player_status = "NO_MEDIA_PRESENT"
    self.Player_time_pos = ""
    self.Player_duration = ""
    self.Player_mute = False
    self.Player_volume = 0
    self.Player_paused = True
    self.Player_event_event = threading.Event()

  def manage_incoming_msg(self):
    while self.Msg_buffer[0] == "run":
      while len(self.Msg_buffer) > 1:
        self.Msg_event.clear()
        msg = self.Msg_buffer.pop(1)
        if not msg:
          continue
        self.logger.log('Lecteur - message reçu: %s' % msg, 2)
        try:
          msg_dict = json.loads(msg)
        except:
          continue
        if 'event' in msg_dict:
          if msg_dict['event'] == "property-change":
            name = msg_dict.get('name', '')
            if name == "duration":
              if 'data' in msg_dict:
                durat_sec = int(msg_dict['data'])
                durat = '%d:%02d:%02d' % (durat_sec // 3600, (durat_sec % 3600) // 60, durat_sec % 60)
                if self.Player_duration != durat:
                  self.Player_duration = durat
                  self.Player_events.append(('CurrentMediaDuration', durat))
                  self.Player_event_event.set()
                  self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('CurrentMediaDuration', durat), 1)
            elif name == "time-pos":
              if 'data' in msg_dict:
                time_sec = int(msg_dict['data'])
                time_pos = '%d:%02d:%02d' % (time_sec // 3600, (time_sec % 3600) // 60, time_sec % 60)
                if self.Player_time_pos != time_pos:
                  self.Player_time_pos = time_pos
                  self.Player_events.append(('RelativeTimePosition', time_pos))
                  self.Player_event_event.set()
                  self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('RelativeTimePosition', time_pos), 2)
              else:
                self.Player_time_pos = ""
                self.Player_events.append(('RelativeTimePosition', ""))
                self.Player_event_event.set()
                self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('RelativeTimePosition', ''), 2)
            elif name == "mute":
              if 'data' in msg_dict:
                self.Player_mute = msg_dict['data']
                self.Player_events.append(('Mute', self.Player_mute))
                self.Player_event_event.set()
                self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('Mute', self.Player_mute), 2)
            elif name == "volume":
              if 'data' in msg_dict:
                self.Player_volume = int(float(msg_dict['data']))
                self.Player_events.append(('Volume', self.Player_volume))
                self.Player_event_event.set()
                self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('Volume', self.Player_volume), 2)
            elif name == "idle-active":
              if msg_dict.get('data', '') == True and self.Player_status != "NO_MEDIA_PRESENT":
                self.Player_status = "STOPPED"
                self.Player_events.append(('TransportState', "STOPPED"))
                self.Player_time_pos = ""
                self.Player_event_event.set()
                self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "STOPPED"), 1)
            elif name == "pause":
              if msg_dict.get('data', '') == True:
                self.Player_paused = True
                if self.Player_status == "PLAYING":
                  self.Player_status = "PAUSED_PLAYBACK"
                  self.Player_events.append(('TransportState', "PAUSED_PLAYBACK"))
                  self.Player_event_event.set()
                  self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "PAUSED_PLAYBACK"), 1)
              elif msg_dict.get('data', '') == False:
                self.Player_paused = False
                if self.Player_status == "PAUSED_PLAYBACK":
                  self.Player_status = "PLAYING"
                  self.Player_events.append(('TransportState', "PLAYING"))
                  self.Player_event_event.set()
                  self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "PLAYING"), 1)
            elif name == "playlist-playing-pos":
              if msg_dict.get('data', '') == 1:
                self.Player_events.append(('Playlist', "1"))
                self.Player_event_event.set()
                self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('Playlist', "1"), 1)
          elif msg_dict['event'] == "start-file":
            self.Player_time_pos = ""
            self.Player_duration = ""
            self.Player_status = "TRANSITIONING"
            self.Player_events.append(('TransportState', "STARTING"))
            self.Player_event_event.set()
            self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "TRANSITIONING"), 2)
          elif msg_dict['event'] == "end-file":
            if msg_dict.get('reason','').lower() == "error":
              self.Player_events.append(('TransportStatus', "ERROR_OCCURRED"))
              self.Player_event_event.set()
              self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportStatus', "ERROR_OCCURRED"), 2)
          elif msg_dict['event'] == 'seek':
            self.Player_status = "TRANSITIONING"
            self.Player_events.append(('TransportState', "TRANSITIONING"))
            self.Player_event_event.set()
            self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "TRANSITIONING"), 2)
          elif msg_dict['event'] == "playback-restart":
            if self.Player_paused:
              self.Player_status = "PAUSED_PLAYBACK"
              self.Player_events.append(('TransportState', "PAUSED_PLAYBACK"))
              self.Player_event_event.set()
              self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "PAUSED_PLAYBACK"), 1)
            else:
              self.Player_status = "PLAYING"
              self.Player_events.append(('TransportState', "PLAYING"))
              self.Player_event_event.set()
              self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "PLAYING"), 1)
      if self.Msg_buffer[0] == "run":
        self.Msg_event.wait()

  def run_mpv(self):
    self.logger.log('Lecteur - lancement', 1)
    try:
      process_result = subprocess.run(r'"%s\%s"' % (IPCmpvControler.SCRIPT_PATH, 'mpv.bat'), env={**os.environ, 'renderer_name': urllib.parse.quote(self.title_name, safe='')}, capture_output=False)
    except:
      pass
    self.logger.log('Lecteur: fermeture', 1)
    if self.Player_status != "STOPPED":
      self.Player_status = "STOPPED"
      self.logger.log('Lecteur - événement enregistré: %s = "%s"' % ('TransportState', "STOPPED"), 1)
      self.Player_events.append(('TransportState', "STOPPED"))
    self.Cmd_buffer[0] = "quit"
    self.Msg_buffer[0] = "quit"
    self.Player_event_event.set()
    kernel32.SetEvent(self.Cmd_Event)

  def run(self):
    self.mpv_thread = threading.Thread(target=self.run_mpv)
    self.mpv_thread.start()
    request_id = 0
    while self.Cmd_buffer[0] != "quit":
      hnd = HANDLE(kernel32.CreateFileW(LPWSTR(r'\\.\pipe\mpv_%s' % urllib.parse.quote(self.title_name, safe='')), DWORD(0xc0000000), DWORD(0), PVOID(0), DWORD(4), DWORD(0x60000000), HANDLE(0)))
      if kernel32.GetLastError() == 2:
        time.sleep(0.5)
      else:
        self.Pipe_handle = hnd
        break
    if kernel32.GetLastError() == 2:
      self.logger.log(LSTRINGS['player_failure'], 0)
      return False
    self.incoming_msg_thread = threading.Thread(target=self.manage_incoming_msg)
    self.incoming_msg_thread.start()
    w = 0
    msg_chunk = ""
    while self.Cmd_buffer[0] == "run":
      kernel32.ResetEvent(self.Cmd_Event)
      if not self.Write_pending and len(self.Cmd_buffer) > 1:
        cmd = self.Cmd_buffer.pop(1)
        msg = None
        try:
          msg = ctypes.create_string_buffer(json.dumps({'command': cmd, 'request_id': request_id}).encode('UTF-8'))
          msg[len(msg) - 1] = b'\n'
        except:
          continue
        if not msg:
          continue
        request_id += 1
        kernel32.WriteFileEx(self.Pipe_handle, msg, DWORD(len(msg)), self.lpOverlapped_w, IPCmpvControler.WriteFileEx_Completion_Routine)
        self.logger.log('Lecteur - message transmis: %s' % msg.value, 2)
        self.Write_pending = True
      if not self.Read_pending:
        self.Pipe_buffer.raw = bytes(10000)
        kernel32.ReadFileEx(self.Pipe_handle, self.Pipe_buffer, DWORD(10000), self.lpOverlapped_r, IPCmpvControler.ReadFileEx_Completion_Routine)
        self.Read_pending = True
      w = kernel32.WaitForSingleObjectEx(self.Cmd_Event, DWORD(-1), BOOL(1))
      if w == 0x000000C0 or w == 0:
        if self.Write_pending:
          self.NumberOfBytesTransferred_w.value = 0
          if kernel32.GetOverlappedResultEx(self.Pipe_handle, self.lpOverlapped_w, ctypes.byref(self.NumberOfBytesTransferred_w), DWORD(1), BOOL(0)) != 0:
            kernel32.ResetEvent(self.lpOverlapped_w.contents.hEvent)
            self.Write_pending = False
            self.logger.log('Lecteur - écrit dans le tuyau: %d octets' % self.NumberOfBytesTransferred_w.value, 2)
        self.NumberOfBytesTransferred_r.value = 0
        if kernel32.GetOverlappedResultEx(self.Pipe_handle, self.lpOverlapped_r, ctypes.byref(self.NumberOfBytesTransferred_r), DWORD(1), BOOL(0)) != 0:
          kernel32.ResetEvent(self.lpOverlapped_r.contents.hEvent)
          self.Read_pending = False
          self.logger.log('Lecteur - lu depuis le tuyau: %d octets' % self.NumberOfBytesTransferred_r.value, 2)
      if not self.Read_pending:
        if self.NumberOfBytesTransferred_r.value != 0:
          msg_list = (msg_chunk + (self.Pipe_buffer.raw[0:self.NumberOfBytesTransferred_r.value] + b"\x00").decode('UTF-8')).splitlines()
          self.Msg_buffer.extend(msg_list[0:-1])
          msg_chunk = msg_list[-1][0:-1]
          self.Msg_event.set()
    self.Msg_buffer[0] = "quit"
    self.Msg_event.set()
    msg = ctypes.create_string_buffer(json.dumps({'command': ['quit'], 'request_id': request_id}).encode('UTF-8'))
    msg[len(msg) - 1] = b'\n'
    kernel32.CancelIoEx(self.Pipe_handle, None)
    kernel32.WriteFileEx(self.Pipe_handle, msg, DWORD(len(msg)), self.lpOverlapped_w, IPCmpvControler.WriteFileEx_Completion_Routine)
    self.logger.log('Lecteur - message transmis: %s' % msg.value, 1)
    kernel32.CloseHandle(self.Pipe_handle)

  def stop(self):
    self.Cmd_buffer[0] = "quit"
    kernel32.SetEvent(self.Cmd_Event)


class DLNAArgument:

  def __init__(self):
    self.Name = None
    self.Direction = None
    self.Event = None
    self.Type = None
    self.AllowedValueList = None
    self.AllowedValueRange = None
    self.DefaultValue = None


class DLNAAction:

  def __init__(self):
    self.Name = None
    self.Arguments = []


class DLNAService:

  def __init__(self):
    self.Type = None
    self.Id = None
    self.ControlURL = None
    self.SubscrEventURL = None
    self.DescURL = None
    self.Actions = []
    self.EventThroughLastChange = None


class DLNASearchServer():

  def __init__(self, renderer, verbosity):
    self.logger = log_event(verbosity)
    self.Renderer = renderer
    self.__shutdown_request = False
    self.__is_shut_down = threading.Event()
    self.__is_shut_down.set()
    self.Sockets = ()

  def handle(self, i, msg, addr):
    sock = self.Sockets[i]
    ip = self.Renderer.Ips[i]
    req = HTTPMessage((msg, sock))
    if req.method != 'M-SEARCH':
      return
    if not req.header('ST', '').lower() in (s.lower() for s in ('ssdp:all', 'upnp:rootdevice', 'urn:schemas-upnp-org:device:MediaRenderer:1', 'urn:schemas-upnp-org:service:AVTransport:1', UDN)):
      return
    self.logger.log('Réception, sur l\'interface %s, d\'un message de recherche de renderer de %s:%s' % (ip, *addr), 2)
    if self.__shutdown_request or self.__is_shut_down.is_set():
      return
    resp = 'HTTP/1.1 200 OK\r\n' \
    'Cache-Control: max-age=1800\r\n' \
    'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
    'Ext: \r\n' \
    'Location: ' + self.Renderer.DescURL % ip + '\r\n' \
    'Server: DLNAmpvRenderer\r\n' \
    'ST: ' + req.header('ST') + '\r\n' \
    'USN: ' + UDN + '::' + req.header('ST') + '\r\n' \
    'Content-Length: 0\r\n' \
    '\r\n'
    try:
      sock.sendto(resp.encode('ISO-8859-1'), addr)
      self.logger.log('Envoi, sur l\'interface %s, de la réponse au message de recherche de renderer de %s:%s' % (ip, *addr), 2)
    except:
      self.logger.log('Échec de l\'envoi, sur l\'interface %s, de la réponse au message de recherche de renderer de %s:%s' % (ip, *addr), 2)

  def serve_forever(self):
    self.__is_shut_down.clear()
    self.__shutdown_request = True
    self.Sockets = tuple(socket.socket(type=socket.SOCK_DGRAM) for ip in self.Renderer.Ips)
    with selectors.DefaultSelector() as selector:
      for i in range(len(self.Renderer.Ips)):
        sock = self.Sockets[i]
        ip = self.Renderer.Ips[i]
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
          sock.bind((ip, 1900))
          sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack('4s4s', socket.inet_aton('239.255.255.250'), socket.inet_aton(ip)))
          selector.register(sock, selectors.EVENT_READ, i)
          self.__shutdown_request = False
          self.logger.log('Mise en place de l\'écoute de recherche de renderer sur l\'interface %s' % ip, 2)
        except:
          self.logger.log('Échec de la mise en place de l\'écoute de recherche de renderer sur l\'interface %s' % ip, 1)
      while not self.__shutdown_request:
        ready = selector.select(0.5)
        if self.__shutdown_request:
          break
        for r in ready:
          try:
            self.handle(r[0].data, *self.Sockets[r[0].data].recvfrom(8192))
          except:
            pass
    self.__shutdown_request = False
    self.__is_shut_down.set()

  def shutdown(self):
    self.__shutdown_request = True
    for sock in self.Sockets:
      try:
        sock.close()
      except:
        pass
    self.__is_shut_down.wait()

  def __enter__(self):
    return self

  def __exit__(self, *args):
    pass


class DLNARequestServer(socketserver.ThreadingTCPServer):

  allow_reuse_address = True
  request_queue_size = 100
  block_on_close = False

  def __init__(self, *args, verbosity, **kwargs):
    self.logger = log_event(verbosity)
    super().__init__(*args, **kwargs)
    self.__dict__['_BaseServer__is_shut_down'].set()

  def server_bind(self):
    try:
      self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except:
      pass
    super().server_bind()

  def process_request_thread(self, request, client_address):
    try:
      self.logger.log('Connexion de %s:%s sur l\'interface %s' % (*client_address, request.getsockname()[0]), 2)
    except:
      pass
    super().process_request_thread(request, client_address)

  def shutdown(self):
    super().shutdown()
    self.socket.close()

  def server_close(self):
    pass


class DLNARequestHandler(socketserver.BaseRequestHandler):

  def __init__(self, *args, renderer, **kwargs):
    self.Renderer = renderer
    try:
      super().__init__(*args, **kwargs)
    except:
      pass

  def handle(self):
    if not self.Renderer.is_request_manager_running:
      return
    req = HTTPMessage(self.request)
    if not self.Renderer.is_request_manager_running or not req.method:
      return
    self.server.logger.log('Réception de la requête %s' % req.method, 2)
    if req.method == 'OPTIONS':
      resp = 'HTTP/1.1 200 OK\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Connection: close\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Allow: OPTIONS, HEAD, GET, POST, SUBSCRIBE, UNSUBSCRIBE\r\n' \
      '\r\n'
      try:
        self.request.sendall(resp.encode('ISO-8859-1'))
        self.server.logger.log('Réponse à la requête %s' % req.method, 2)
      except:
        self.server.logger.log('Échec de la réponse à la requête %s' % req.method, 2)
    elif req.method in ('GET', 'HEAD'):
      resp = 'HTTP/1.1 200 OK\r\n' \
      'Content-Type: ##type##\r\n' \
      'Content-Length: ##len##\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Connection: close\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      '\r\n'
      resp_err = 'HTTP/1.1 404 File not found\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_body = b''
      self.server.logger.log('Réception de la requête %s %s' % (req.method, req.path), 2)
      dict_scpd = {'/D_S': 'Device_SCPD', '/RC_S': 'RenderingControl_SCPD', '/CM_S': 'ConnectionManager_SCPD', '/AVT_S': 'AVTransport_SCPD'}
      if req.path.upper() in dict_scpd:
        resp_body = (getattr(DLNARenderer, dict_scpd[req.path]) % (() if req.path != '/AVT_S' else ((DLNARenderer.AVTransport_SCPD_Gapless if self.Renderer.Gapless else ''),))).encode('utf-8')
        try:
          if req.method == 'GET':
            self.request.sendall(resp.replace('##type##', 'text/xml; charset="utf-8"').replace('##len##', str(len(resp_body))).encode('ISO-8859-1') + resp_body)
          else:
            self.request.sendall(resp.replace('##type##', 'text/xml; charset="utf-8"').replace('##len##', str(len(resp_body))).encode('ISO-8859-1'))
          self.server.logger.log('Réponse à la requête %s: %s' % (req.method, dict_scpd[req.path]), 1)
        except:
          self.server.logger.log('Échec de la réponse à la requête %s: %s' % (req.method, dict_scpd[req.path]), 1)
      elif req.path.lower() == '/icon.png':
        resp_body = self.Renderer.Icon
        try:
          if req.method == 'GET':
            self.request.sendall(resp.replace('##type##', 'image/png').replace('##len##', str(len(resp_body))).encode('ISO-8859-1') + resp_body)
          else:
            self.request.sendall(resp.replace('##type##', 'image/png').replace('##len##', str(len(resp_body))).encode('ISO-8859-1'))
          self.server.logger.log('Réponse à la requête %s /ICON.PNG' % req.method, 1)
        except:
          self.server.logger.log('Échec de la réponse à la requête %s /ICON.PNG' % req.method, 1)
      else:
        try:
          self.request.sendall(resp_err.encode('ISO-8859-1'))
        except:
          pass
        self.server.logger.log('Rejet de la requête %s %s - code 404' % (req.method, req.path), 2)
    elif req.method == 'SUBSCRIBE':
      resp = 'HTTP/1.1 200 OK\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'SID: ##sid##\r\n' \
      'Timeout: Second-##sec##\r\n' \
      'Content-Length: 0\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_err_nf = 'HTTP/1.1 404 File not found\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_err_pf = 'HTTP/1.1 412 Precondition Failed\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      self.server.logger.log('Réception de la requête SUBSCRIBE %s' % req.path, 2)
      dict_serv = {'/RC_E': 'RenderingControl', '/CM_E': 'ConnectionManager', '/AVT_E': 'AVTransport'}
      serv = dict_serv.get(req.path, '')
      if not serv:
        try:
          self.request.sendall(resp_err_nf.encode('ISO-8859-1'))
        except:
          pass
        self.server.logger.log('Rejet de la requête SUBSCRIBE %s - code 404' % req.path, 2)
      elif req.header('NT', '').lower() == 'upnp:event':
        timeout = req.header('TIMEOUT', '').lower()
        if timeout[:7].lower() == 'second-':
          timeout = timeout[7:]
          if timeout.isnumeric():
            timeout = int(float(timeout))
            if timeout <= 0:
              timeout = 10000
          else:
            timeout = 10000
        else:
          timeout = 10000
        try:
          callback = req.header('CALLBACK').lstrip('< ').rstrip('> ')
          ip = self.request.getsockname()[0]
        except:
          callback = None
        if callback and self.Renderer.is_events_manager_running:
          event_sub = EventSubscription(self.Renderer, serv, timeout, callback, ip)
          self.Renderer.EventSubscriptions.append(event_sub)
          event_sub.start_event_management()
          try:
            self.request.sendall(resp.replace('##sid##', event_sub.SID).replace('##sec##', str(timeout)).encode('ISO-8859-1'))
            self.server.logger.log('Réponse à la requête SUBSCRIBE %s: %s' % (req.path, event_sub.SID), 1)
          except:
            self.server.logger.log('Échec de la réponse à la requête SUBSCRIBE %s: %s' % (req.path, event_sub.SID), 1)
          if not self.Renderer.is_events_manager_running:
            event_sub.stop_event_management()
        else:
          try:
            self.request.sendall(resp_err_pf.encode('ISO-8859-1'))
          except:
            pass
          self.server.logger.log('Rejet de la requête SUBSCRIBE %s - code 412' % req.path, 2)
      else:
        sid = req.header('SID', '').lower()
        event_sub = next((e_s for e_s in self.Renderer.EventSubscriptions if (e_s.Service.Id.lower()[23:] == serv.lower() and e_s.SID.lower() == sid)), None)
        timeout = req.header('TIMEOUT', '').lower()
        if timeout[:7].lower() == 'second-':
          timeout = timeout[7:]
          if timeout.isnumeric():
            timeout = int(float(timeout))
            if timeout <= 0:
              timeout = 10000
          else:
            timeout = 10000
        else:
          timeout = 10000
        sub_time = time.time()
        if event_sub:
          if event_sub.End_time < sub_time:
            event_sub = None
        if event_sub:
          event_sub.set_end_time(sub_time + timeout)
          try:
            self.request.sendall(resp.replace('##sid##', event_sub.SID).replace('##sec##', str(timeout)).encode('ISO-8859-1'))
            self.server.logger.log('Réponse à la requête SUBSCRIBE %s' % sid, 1)
          except:
            self.server.logger.log('Échec de la réponse à la requête SUBSCRIBE %s' % sid, 1)
        else:
          self.request.sendall(resp_err_pf.encode('ISO-8859-1'))
          self.server.logger.log('Rejet de la requête SUBSCRIBE %s - code 412' % sid, 2)
    elif req.method == 'UNSUBSCRIBE':
      resp = 'HTTP/1.1 200 OK\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'SID: ##sid##\r\n' \
      'Content-Length: 0\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_err_nf = 'HTTP/1.1 404 File not found\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_err_pf = 'HTTP/1.1 412 Precondition Failed\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      self.server.logger.log('Réception de la requête UNSUBSCRIBE %s' % req.path, 2)
      dict_serv = {'/RC_E': 'RenderingControl', '/CM_E': 'ConnectionManager', '/AVT_E': 'AVTransport'}
      serv = dict_serv.get(req.path, '')
      if not serv:
        try:
          self.request.sendall(resp_err_nf.encode('ISO-8859-1'))
        except:
          pass
        self.server.logger.log('Rejet de la requête UNSUBSCRIBE %s - code 404' % req.path, 2)
      else:
        sid = req.header('SID', '').lower()
        event_sub = next((e_s for e_s in self.Renderer.EventSubscriptions if (e_s.Service.Id.lower()[23:] == serv.lower() and e_s.SID.lower() == sid)), None)
        sub_time = time.time()
        if event_sub:
          if event_sub.End_time < sub_time:
            event_sub.EventEvent.set()
            event_sub = None
        if event_sub:
          event_sub.stop_event_management()
          try:
            self.request.sendall(resp.replace('##sid##', event_sub.SID).replace('##sec##', str(int(0))).encode('ISO-8859-1'))
            self.server.logger.log('Réponse à la requête UNSUBSCRIBE %s' % sid, 1)
          except:
            self.server.logger.log('Échec de la réponse à la requête UNSUBSCRIBE %s' % sid, 1)
        else:
          self.request.sendall(resp_err_pf.encode('ISO-8859-1'))
          self.server.logger.log('Rejet de la requête UNSUBSCRIBE %s - code 412' % sid, 2)
    elif req.method == 'POST':
      resp = 'HTTP/1.1 200 OK\r\n' \
      'Content-Length: ##len##\r\n' \
      'Content-Type: text/xml; charset="utf-8"\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Ext:\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_body = '<?xml version="1.0" encoding="utf-8"?>\n' \
      '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n' \
      '<s:Body>\n' \
      '<u:##act##Response xmlns:u="urn:schemas-upnp-org:service:##serv##:1">\n' \
      '##prop##' \
      '</u:##act##Response>\n' \
      '</s:Body>\n' \
      '</s:Envelope>'
      resp_err_nf = 'HTTP/1.1 404 File not found\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_err_br = 'HTTP/1.1 400 Bad Request\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      resp_err_ise = 'HTTP/1.1 500 Internal Server Error\r\n' \
      'Content-Length: ##len##\r\n' \
      'Content-Type: text/xml; charset="utf-8"\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Ext:\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      '\r\n'
      resp_err_ise401_body = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n' \
      '<s:Body>\n' \
      '<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault>\n' \
      '</s:Body>\n' \
      '</s:Envelope>'
      resp_err_ise402_body = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n' \
      '<s:Body>\n' \
      '<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>402</errorCode><errorDescription>Invalid Args</errorDescription></UPnPError></detail></s:Fault>\n' \
      '</s:Body>\n' \
      '</s:Envelope>'
      resp_err_ise701_body = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n' \
      '<s:Body>\n' \
      '<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>701</errorCode><errorDescription>Transition not available</errorDescription></UPnPError></detail></s:Fault>\n' \
      '</s:Body>\n' \
      '</s:Envelope>'
      resp_err_ise716_body = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n' \
      '<s:Body>\n' \
      '<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>716</errorCode><errorDescription>Resource not found</errorDescription></UPnPError></detail></s:Fault>\n' \
      '</s:Body>\n' \
      '</s:Envelope>'
      self.server.logger.log('Réception de la requête POST %s' % req.path, 2)
      dict_serv = {'/RC_C': 'RenderingControl', '/CM_C': 'ConnectionManager', '/AVT_C': 'AVTransport'}
      serv = dict_serv.get(req.path, '')
      if not serv:
        try:
          self.request.sendall(resp_err_nf.encode('ISO-8859-1'))
        except:
          pass
        self.server.logger.log('Rejet de la requête POST %s - code 404' % req.path, 2)
      else:
        act = req.header('SOAPACTION', '')
        act = act.partition('service:' + serv + ':1#')[2].strip(' \'"')
        if not req.body:
          try:
            self.request.sendall(resp_err_br.encode('ISO-8859-1'))
          except:
            pass
          self.server.logger.log('Rejet de la requête POST %s-%s - code 400' % (serv, act), 2)
        try:
          root_xml = minidom.parseString(req.body)
          if root_xml.documentElement.tagName.split(':', 1)[1].lower() != 'envelope':
            raise
          node = None
          for ch_node in root_xml.documentElement.childNodes:
            if ch_node.nodeType == ch_node.ELEMENT_NODE:
              if node:
                raise
              else:
                node = ch_node
          if node.tagName.split(':', 1)[1].lower() != 'body':
            raise
          a_node = None
          for ch_node in node.childNodes:
            if ch_node.nodeType == ch_node.ELEMENT_NODE:
              if a_node:
                raise
              else:
                a_node = ch_node
          if a_node.tagName.split(':', 1)[1].lower() != act.lower():
            raise
          args = []
          for ch_node in a_node.childNodes:
            if ch_node.nodeType == ch_node.ELEMENT_NODE:
              prop_name = ch_node.tagName
              prop_value = _XMLGetNodeText(ch_node)
              if prop_name:
                args.append((prop_name, prop_value))
              else:
                raise
        except:
          act = ''
        if act:
          res, out_args = self.Renderer.process_action(serv, act, args, req.header('USER-AGENT', ''))
          if not self.Renderer.is_request_manager_running:
            return
          if res == '200':
            resp_body = resp_body.replace('##act##', act).replace('##serv##', serv)
            for prop_name in out_args:
              if out_args[prop_name] != None:
                resp_body = resp_body.replace('##prop##', '<' + prop_name + '>' + html.escape(out_args[prop_name]) + '</' + prop_name + '>\n##prop##')
            resp_body = resp_body.replace('##prop##', '').encode('UTF-8')
            try:
              self.request.sendall(resp.replace('##len##', str(len(resp_body))).encode('ISO-8859-1') + resp_body)
              self.server.logger.log('Réponse à la requête POST %s-%s' % (serv, act), 1)
            except:
              self.server.logger.log('Échec de la réponse à la requête POST %s-%s' % (serv, act), 1)
          elif res in ('401', '402', '701', '716'):
            resp_body = locals()['resp_err_ise%s_body' % res].encode('UTF-8')
            try:
              self.request.sendall(resp_err_ise.replace('##len##', str(len(resp_body))).encode('ISO-8859-1') + resp_body)
            except:
              pass
            self.server.logger.log('Réponse d\'échec de la requête POST %s-%s - code %s' % (serv, act, res), 1)
          else:
            try:
              self.request.sendall(resp_err_br.encode('ISO-8859-1'))
            except:
              pass
            self.server.logger.log('Réponse d\'échec de la requête POST %s-%s - code 400' % (serv, act), 1)
        else:
          try:
            self.request.sendall(resp_err_br.encode('ISO-8859-1'))
          except:
            pass
          self.server.logger.log('Rejet de la requête POST %s - code 400' % serv, 2)
    else:
      resp_err = 'HTTP/1.1 501 Not Implemented\r\n' \
      'Content-Length: 0\r\n' \
      'Date: ' + email.utils.formatdate(time.time(), usegmt=True) + '\r\n' \
      'Server: DLNAmpvRenderer\r\n' \
      'Connection: close\r\n' \
      '\r\n'
      try:
        self.request.sendall(resp_err_br.encode('ISO-8859-1'))
      except:
        pass
      self.server.logger.log('Rejet de la requête POST %s - code 501' % req.method, 2)


class EventSubscription:

  def __init__(self, renderer, service, timeout, callback, ip):
    self.Renderer = renderer
    self.logger = self.Renderer.logger
    self.Service = next((serv for serv in renderer.Services if serv.Id.lower() == ('urn:upnp-org:serviceId:' + service).lower()), None)
    sub_time = time.time()
    self.SID = 'uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, service + str(sub_time)))
    self.End_time_lock = threading.Lock()
    self.End_time = sub_time + timeout
    self.Callback = callback
    self.Ip = ip
    self.EventEvent = threading.Event()
    self.SEQ = 0
    self.Events = []
    self.PConnection = [None]

  def set_end_time(self, end_time):
    self.End_time_lock.acquire()
    if self.End_time !=0:
      self.End_time = end_time
    self.End_time_lock.release()

  def _event_manager(self):
    self.logger.log('Souscription %s - démarrage, sur l\'interface %s, du gestionnaire de notification d\'événement' % (self.SID, self.Ip), 2)
    nb_skipped = 0
    while self.End_time > 0:
      self.EventEvent.clear()
      while self.End_time > 0 and self.Events:
        event = self.Events.pop(0)
        if len(event) == 2 and event[0][0].lower() == 'CurrentMediaDuration'.lower():
          if len(self.Events) > 0:
            if len(self.Events[0]) == 2 and self.Events[0][0][0].lower() == 'CurrentMediaDuration'.lower():
              if len(self.Events) >= 5 or nb_skipped < len(self.Events) - 1:
                nb_skipped += 1
                continue
        if len(event) == 1 and event[0][0].lower() == 'Volume channel="Master"'.lower():
          if len(self.Events) > 0:
            if len(self.Events[0]) == 1 and self.Events[0][0][0].lower() == 'Volume channel="Master"'.lower():
              continue
        nb_skipped = 0
        msg_headers= {
          'Content-Type': 'text/xml; charset="utf-8"',
          'NT': 'upnp:event',
          'NTS': 'upnp:propchange',
          'SID': self.SID,
          'SEQ': str(self.SEQ),
          'Connection': 'close',
          'User-Agent': 'DLNAmpvRenderer',
          'Cache-Control': 'no-cache'
        }
        if self.Service.Id[23:].lower() == 'ConnectionManager'.lower():
          msg_body = '<?xml version="1.0"?>\n' \
        '<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">##prop##</e:propertyset>'
          for prop_name, prop_value in event:
            msg_body = msg_body.replace('##prop##', '<e:property><' + prop_name + '>' + html.escape(prop_value) + '</' + prop_name + '></e:property>' + '##prop##')
          msg_body = msg_body.replace('##prop##', '').encode('UTF-8')
        else:
          msg_body = '<?xml version="1.0"?>\n' \
        '<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0"><e:property><LastChange>&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/%s/&quot;&gt;&lt;InstanceID val=&quot;0&quot;&gt;##prop##&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange></e:property></e:propertyset>' % ('AVT' if 'AVTransport'.lower() in self.Service.Id.lower() else 'RCS')
          for prop_name, prop_value in event:
            msg_body = msg_body.replace('##prop##', html.escape('<' + prop_name + ' val="' + html.escape(prop_value) + '"/>##prop##'))
          msg_body = msg_body.replace('##prop##', '').encode('UTF-8')
        msg_headers['Content-Length'] = str(len(msg_body))
        try:
          resp = HTTPRequest(self.Callback, method='NOTIFY', headers=msg_headers, data=msg_body, pconnection=self.PConnection, ip=self.Ip)
          self.logger.log('Souscription %s - envoi de la notification d\'événement %d: ' % (self.SID, self.SEQ) + ', '.join('(' + prop_name + ': ' + prop_value + ')' for (prop_name, prop_value) in event), 2)
          if resp.code == '200':
            self.logger.log('Souscription %s - réception de l\'accusé de réception de la notification d\'événement %d' % (self.SID, self.SEQ), 2)
          else:
            self.logger.log('Souscription %s - échec de la réception de l\'accusé de réception de la notification d\'événement %d - code %s' % (self.SID, self.SEQ, resp.code), 2)
        except:
          self.logger.log('Souscription %s - échec de l\'envoi de la notification d\'événement %d' % (self.SID, self.SEQ), 2)
        self.SEQ += 1
      cur_time = time.time()
      if self.End_time >= cur_time :
        self.EventEvent.wait(self.End_time - cur_time + 1)
        if self.End_time < time.time():
          self.set_end_time(0)
      else:
        self.set_end_time(0)
    self.logger.log('Souscription %s - arrêt du gestionnaire de notification d\'événement' % self.SID, 2)

  def start_event_management(self):
    if 'AVTransport'.lower() in self.Service.Id.lower():
      self.Events = [(('TransportState', self.Renderer.TransportState), ('TransportStatus', "OK"), ('TransportPlaySpeed', "1"), ('NumberOfTracks', "1" if self.Renderer.AVTransportURI else "0"), ('CurrentMediaDuration', self.Renderer.CurrentMediaDuration), ('AVTransportURI', self.Renderer.AVTransportURI), ('AVTransportURIMetaData', self.Renderer.AVTransportURIMetaData), ('PlaybackStorageMedium', "NETWORK,NONE"), ('CurrentTrack', "1" if self.Renderer.AVTransportURI else "0"), ('CurrentTrackDuration', self.Renderer.CurrentMediaDuration), ('CurrentTrackMetaData', self.Renderer.AVTransportURIMetaData), ('CurrentTrackURI', self.Renderer.AVTransportURI), ('CurrentTransportActions', {'TRANSITIONING': "Stop", 'STOPPED': "Play,Seek",'PAUSED_PLAYBACK': "Play,Stop,Seek" ,'PLAYING': "Pause,Stop,Seek"}.get(self.Renderer.TransportState, "")), ('CurrentPlayMode', "NORMAL"))]
    elif 'RenderingControl'.lower() in self.Service.Id.lower():
      self.Events = [(('Mute channel="Master"', self.Renderer.Mute), ('Volume channel="Master"', self.Renderer.Volume))]
    elif 'ConnectionManager'.lower() in self.Service.Id.lower():
      self.Events = [(('SourceProtocolInfo', ""), ('SinkProtocolInfo', DLNARenderer.Sink))]
    manager_thread = threading.Thread(target=self._event_manager)
    if self.Renderer.is_events_manager_running:
      manager_thread.start()

  def stop_event_management(self):
    self.set_end_time(0)
    try:
      self.PConnection[0].close()
    except:
      pass
    self.EventEvent.set()


class DLNARenderer:

  Device_SCPD = \
  '''<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" xmlns:pnpx="http://schemas.microsoft.com/windows/pnpx/2005/11" xmlns:df="http://schemas.microsoft.com/windows/2008/09/devicefoundation" xmlns:sec="http://www.sec.co.kr/dlna">
 <specVersion>
  <major>1</major>
  <minor>0</minor>
 </specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
  <pnpx:X_compatibleId>MS_DigitalMediaDeviceClass_DMR_V001</pnpx:X_compatibleId>
  <pnpx:X_deviceCategory>MediaDevices</pnpx:X_deviceCategory>
  <df:X_deviceCategory>Multimedia.DMR</df:X_deviceCategory>
  <dlna:X_DLNADOC xmlns:dlna="urn:schemas-dlna-org:device-1-0">DMR-1.50</dlna:X_DLNADOC>
  <friendlyName>''' + html.escape(NAME) + '''</friendlyName>
  <manufacturer>PCigales</manufacturer>
  <manufacturerURL>https://github.com/PCigales</manufacturerURL>
  <modelDescription>DLNA mpv renderer</modelDescription>
  <modelName>DLNA mpv renderer</modelName>
  <modelNumber>1.0</modelNumber>
  <modelURL>https://github.com/PCigales</modelURL>
  <serialNumber>1.0</serialNumber>
  <UDN>''' + UDN + '''</UDN>
  <iconList>
   <icon>
    <mimetype>image/png</mimetype>
    <width>72</width>
    <height>72</height>
    <depth>24</depth>
    <url>/icon.png</url>
   </icon>
  </iconList>
  <serviceList>
   <service>
    <serviceType>urn:schemas-upnp-org:service:RenderingControl:1</serviceType>
    <serviceId>urn:upnp-org:serviceId:RenderingControl</serviceId>
    <controlURL>/RC_C</controlURL>
    <eventSubURL>/RC_E</eventSubURL>
    <SCPDURL>/RC_S</SCPDURL>
   </service>
   <service>
    <serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType>
    <serviceId>urn:upnp-org:serviceId:ConnectionManager</serviceId>
    <controlURL>/CM_C</controlURL>
    <eventSubURL>/CM_E</eventSubURL>
    <SCPDURL>/CM_S</SCPDURL>
   </service>
   <service>
    <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
    <serviceId>urn:upnp-org:serviceId:AVTransport</serviceId>
    <controlURL>/AVT_C</controlURL>
    <eventSubURL>/AVT_E</eventSubURL>
    <SCPDURL>/AVT_S</SCPDURL>
   </service>
  </serviceList>
  <sec:ProductCap>Y2020,WebURIPlayable,SeekTRACK_NR,NavigateInPause</sec:ProductCap>
  <pnpx:X_hardwareId>VEN_0105&amp;DEV_VD0001</pnpx:X_hardwareId>
 </device>
</root>'''
  RenderingControl_SCPD = \
  '''<?xml version="1.0" encoding="utf-8"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <actionList>
    <action>
      <name>GetMute</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Channel</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentMute</name>
          <direction>out</direction>
          <relatedStateVariable>Mute</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>SetMute</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Channel</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>
        </argument>
        <argument>
          <name>DesiredMute</name>
          <direction>in</direction>
          <relatedStateVariable>Mute</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>GetVolume</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Channel</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentVolume</name>
          <direction>out</direction>
          <relatedStateVariable>Volume</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>SetVolume</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Channel</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>
        </argument>
        <argument>
          <name>DesiredVolume</name>
          <direction>in</direction>
          <relatedStateVariable>Volume</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
  </actionList>
  <serviceStateTable>
    <stateVariable sendEvents="yes">
      <name>LastChange</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>Mute</name>
      <dataType>boolean</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>Volume</name>
      <dataType>ui2</dataType>
      <allowedValueRange>
        <minimum>0</minimum>
        <maximum>100</maximum>
        <step>1</step>
      </allowedValueRange>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_Channel</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>Master</allowedValue>
      </allowedValueList>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_InstanceID</name>
      <dataType>ui4</dataType>
    </stateVariable>
  </serviceStateTable>
</scpd>'''
  ConnectionManager_SCPD = \
'''<?xml version="1.0" encoding="utf-8"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <actionList>
    <action>
      <name>GetCurrentConnectionInfo</name>
      <argumentList>
        <argument>
          <name>ConnectionID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_ConnectionID</relatedStateVariable>
        </argument>
        <argument>
          <name>RcsID</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_RcsID</relatedStateVariable>
        </argument>
        <argument>
          <name>AVTransportID</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_AVTransportID</relatedStateVariable>
        </argument>
        <argument>
          <name>ProtocolInfo</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_ProtocolInfo</relatedStateVariable>
        </argument>
        <argument>
          <name>PeerConnectionManager</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_ConnectionManager</relatedStateVariable>
        </argument>
        <argument>
          <name>PeerConnectionID</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_ConnectionID</relatedStateVariable>
        </argument>
        <argument>
          <name>Direction</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_Direction</relatedStateVariable>
        </argument>
        <argument>
          <name>Status</name>
          <direction>out</direction>
          <relatedStateVariable>A_ARG_TYPE_ConnectionStatus</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>GetProtocolInfo</name>
      <argumentList>
        <argument>
          <name>Source</name>
          <direction>out</direction>
          <relatedStateVariable>SourceProtocolInfo</relatedStateVariable>
        </argument>
        <argument>
          <name>Sink</name>
          <direction>out</direction>
          <relatedStateVariable>SinkProtocolInfo</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
  </actionList>
  <serviceStateTable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_ProtocolInfo</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_ConnectionStatus</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>OK</allowedValue>
        <allowedValue>ContentFormatMismatch</allowedValue>
        <allowedValue>InsufficientBandwidth</allowedValue>
        <allowedValue>UnreliableChannel</allowedValue>
        <allowedValue>Unknown</allowedValue>
      </allowedValueList>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_AVTransportID</name>
      <dataType>i4</dataType>
      <defaultValue>0</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_RcsID</name>
      <dataType>i4</dataType>
      <defaultValue>0</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_ConnectionID</name>
      <dataType>i4</dataType>
      <defaultValue>0</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_ConnectionManager</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="yes">
      <name>SourceProtocolInfo</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="yes">
      <name>SinkProtocolInfo</name>
      <dataType>string</dataType>
      <defaultValue></defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_Direction</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>Input</allowedValue>
        <allowedValue>Output</allowedValue>
      </allowedValueList>
    </stateVariable>
  </serviceStateTable>
</scpd>'''
  AVTransport_SCPD_Gapless = \
  '''
    <action>
      <name>SetNextAVTransportURI</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>NextURI</name>
          <direction>in</direction>
          <relatedStateVariable>NextAVTransportURI</relatedStateVariable>
        </argument>
        <argument>
          <name>NextURIMetaData</name>
          <direction>in</direction>
          <relatedStateVariable>NextAVTransportURIMetaData</relatedStateVariable>
        </argument>
      </argumentList>
    </action>'''
  AVTransport_SCPD = \
  '''<?xml version="1.0" encoding="utf-8"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <actionList>
    <action>
      <name>Play</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Speed</name>
          <direction>in</direction>
          <relatedStateVariable>TransportPlaySpeed</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>Stop</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>GetMediaInfo</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>NrTracks</name>
          <direction>out</direction>
          <relatedStateVariable>NumberOfTracks</relatedStateVariable>
          <defaultValue>0</defaultValue>
        </argument>
        <argument>
          <name>MediaDuration</name>
          <direction>out</direction>
          <relatedStateVariable>CurrentMediaDuration</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentURI</name>
          <direction>out</direction>
          <relatedStateVariable>AVTransportURI</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentURIMetaData</name>
          <direction>out</direction>
          <relatedStateVariable>AVTransportURIMetaData</relatedStateVariable>
        </argument>
        <argument>
          <name>NextURI</name>
          <direction>out</direction>
          <relatedStateVariable>NextAVTransportURI</relatedStateVariable>
        </argument>
        <argument>
          <name>NextURIMetaData</name>
          <direction>out</direction>
          <relatedStateVariable>NextAVTransportURIMetaData</relatedStateVariable>
        </argument>
        <argument>
          <name>PlayMedium</name>
          <direction>out</direction>
          <relatedStateVariable>PlaybackStorageMedium</relatedStateVariable>
        </argument>
        <argument>
          <name>RecordMedium</name>
          <direction>out</direction>
          <relatedStateVariable>RecordStorageMedium</relatedStateVariable>
        </argument>
        <argument>
          <name>WriteStatus</name>
          <direction>out</direction>
          <relatedStateVariable>RecordMediumWriteStatus</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>SetAVTransportURI</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentURI</name>
          <direction>in</direction>
          <relatedStateVariable>AVTransportURI</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentURIMetaData</name>
          <direction>in</direction>
          <relatedStateVariable>AVTransportURIMetaData</relatedStateVariable>
        </argument>
      </argumentList>
    </action>%s
    <action>
      <name>GetTransportInfo</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentTransportState</name>
          <direction>out</direction>
          <relatedStateVariable>TransportState</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentTransportStatus</name>
          <direction>out</direction>
          <relatedStateVariable>TransportStatus</relatedStateVariable>
        </argument>
        <argument>
          <name>CurrentSpeed</name>
          <direction>out</direction>
          <relatedStateVariable>TransportPlaySpeed</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>Pause</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>Seek</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Unit</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_SeekMode</relatedStateVariable>
        </argument>
        <argument>
          <name>Target</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_SeekTarget</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>GetPositionInfo</name>
      <argumentList>
        <argument>
          <name>InstanceID</name>
          <direction>in</direction>
          <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>
        </argument>
        <argument>
          <name>Track</name>
          <direction>out</direction>
          <relatedStateVariable>CurrentTrack</relatedStateVariable>
        </argument>
        <argument>
          <name>TrackDuration</name>
          <direction>out</direction>
          <relatedStateVariable>CurrentTrackDuration</relatedStateVariable>
        </argument>
        <argument>
          <name>TrackMetaData</name>
          <direction>out</direction>
          <relatedStateVariable>CurrentTrackMetaData</relatedStateVariable>
        </argument>
        <argument>
          <name>TrackURI</name>
          <direction>out</direction>
          <relatedStateVariable>CurrentTrackURI</relatedStateVariable>
        </argument>
        <argument>
          <name>RelTime</name>
          <direction>out</direction>
          <relatedStateVariable>RelativeTimePosition</relatedStateVariable>
        </argument>
        <argument>
          <name>AbsTime</name>
          <direction>out</direction>
          <relatedStateVariable>AbsoluteTimePosition</relatedStateVariable>
        </argument>
        <argument>
          <name>RelCount</name>
          <direction>out</direction>
          <relatedStateVariable>RelativeCounterPosition</relatedStateVariable>
        </argument>
        <argument>
          <name>AbsCount</name>
          <direction>out</direction>
          <relatedStateVariable>AbsoluteCounterPosition</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
  </actionList>
  <serviceStateTable>
    <stateVariable sendEvents="no">
      <name>TransportState</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>STOPPED</allowedValue>
        <allowedValue>PAUSED_PLAYBACK</allowedValue>
        <allowedValue>PLAYING</allowedValue>
        <allowedValue>TRANSITIONING</allowedValue>
        <allowedValue>NO_MEDIA_PRESENT</allowedValue>
      </allowedValueList>
      <defaultValue>NO_MEDIA_PRESENT</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>TransportStatus</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>OK</allowedValue>
        <allowedValue>ERROR_OCCURRED</allowedValue>
      </allowedValueList>
      <defaultValue>OK</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>TransportPlaySpeed</name>
      <dataType>string</dataType>
      <defaultValue>1</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>NumberOfTracks</name>
      <dataType>ui4</dataType>
      <allowedValueRange>
        <minimum>0</minimum>
        <maximum>4294967295</maximum>
      </allowedValueRange>
      <defaultValue>0</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>CurrentMediaDuration</name>
      <dataType>string</dataType>
      <defaultValue>00:00:00</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>AVTransportURI</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>AVTransportURIMetaData</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>PlaybackStorageMedium</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>NONE</allowedValue>
        <allowedValue>NETWORK</allowedValue>
      </allowedValueList>
      <defaultValue>NONE</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>CurrentTrack</name>
      <dataType>ui4</dataType>
      <allowedValueRange>
        <minimum>0</minimum>
        <maximum>4294967295</maximum>
        <step>1</step>
      </allowedValueRange>
      <defaultValue>0</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>CurrentTrackDuration</name>
      <dataType>string</dataType>
      <defaultValue>00:00:00</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>CurrentTrackMetaData</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>CurrentTrackURI</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>RelativeTimePosition</name>
      <dataType>string</dataType>
      <defaultValue>00:00:00</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>AbsoluteTimePosition</name>
      <dataType>string</dataType>
      <defaultValue>00:00:00</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>NextAVTransportURI</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>NextAVTransportURIMetaData</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>CurrentTransportActions</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>RecordStorageMedium</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>NOT_IMPLEMENTED</allowedValue>
      </allowedValueList>
      <defaultValue>NOT_IMPLEMENTED</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>RecordMediumWriteStatus</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>NOT_IMPLEMENTED</allowedValue>
      </allowedValueList>
      <defaultValue>NOT_IMPLEMENTED</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>RelativeCounterPosition</name>
      <dataType>i4</dataType>
      <defaultValue>2147483647</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>AbsoluteCounterPosition</name>
      <dataType>i4</dataType>
      <defaultValue>2147483647</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="yes">
      <name>LastChange</name>
      <dataType>string</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_InstanceID</name>
      <dataType>ui4</dataType>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_SeekMode</name>
      <dataType>string</dataType>
      <allowedValueList>
        <allowedValue>TRACK_NR</allowedValue>
        <allowedValue>REL_TIME</allowedValue>
        <allowedValue>ABS_TIME</allowedValue>
        <allowedValue>ABS_COUNT</allowedValue>
        <allowedValue>REL_COUNT</allowedValue>
        <allowedValue>FRAME</allowedValue>
      </allowedValueList>
      <defaultValue>REL_TIME</defaultValue>
    </stateVariable>
    <stateVariable sendEvents="no">
      <name>A_ARG_TYPE_SeekTarget</name>
      <dataType>string</dataType>
    </stateVariable>
  </serviceStateTable>
</scpd>'''
  Sink = \
  'http-get:*:audio/L16:DLNA.ORG_PN=LPCM,' \
  'http-get:*:audio/mpeg:DLNA.ORG_PN=MP3,' \
  'http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_SM,' \
  'http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_MED,' \
  'http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_LRG,' \
  'http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_TN,' \
  'http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_SM_ICO,' \
  'http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_LRG_ICO,' \
  'http-get:*:image/png:DLNA.ORG_PN=PNG_TN,' \
  'http-get:*:image/png:DLNA.ORG_PN=PNG_SM_ICO,' \
  'http-get:*:image/png:DLNA.ORG_PN=PNG_LRG_ICO,' \
  'http-get:*:image/png:DLNA.ORG_PN=PNG_LRG,' \
  'http-get:*:audio/vnd.dolby.dd-raw:DLNA.ORG_PN=AC3,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AMR_3GPP,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=AMR_WBplus,' \
  'http-get:*:audio/x-sony-oma:DLNA.ORG_PN=ATRAC3plus,' \
  'http-get:*:audio/mpeg:DLNA.ORG_PN=MP3X,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=AAC_ADTS,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=AAC_ADTS_320,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_ISO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_ISO_320,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_LTP_ISO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_LTP_MULT5_ISO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_LTP_MULT7_ISO,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=AAC_MULT5_ADTS,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_MULT5_ISO,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAAC_L2_ADTS,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAAC_L2_ISO,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAAC_L3_ADTS,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAAC_L3_ISO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAAC_MULT5_ISO,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAAC_L2_ADTS_320,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAAC_L2_ISO_320,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=BSAC_ISO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=BSAC_MULT5_ISO,' \
  'http-get:*:audio/x-ms-wma:DLNA.ORG_PN=WMABASE,' \
  'http-get:*:audio/x-ms-wma:DLNA.ORG_PN=WMAFULL,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG1,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_PS_NTSC,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_PS_NTSC_XAC3,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_PS_PAL,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_PS_PAL_XAC3,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_NA_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_NA,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_NA_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_NA_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_NA,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_NA_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_HD_NA_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_EU,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_EU_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_EU_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_KO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_KO_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_KO_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_KO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_KO_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_HD_KO_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_KO_XAC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_KO_XAC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_HD_KO_XAC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_NA_XAC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_HD_NA_XAC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_HD_NA_XAC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_KO_XAC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_KO_XAC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_KO_XAC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_NA_XAC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_SD_NA_XAC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_NA_XAC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_MP_LL_AAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_MP_LL_AAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_MP_LL_AAC_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_ES_PAL,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_ES_NTSC,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_ES_PAL_XAC3,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_ES_NTSC_XAC3,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_ATRAC3plus,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_AAC_LTP,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L2_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L2_AMR,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_AAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_AAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_SP_AAC_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_MPEG1_L3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_MPEG1_L3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_SP_MPEG1_L3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_AC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_SP_AC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_MPEG2_L2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_SP_MPEG2_L2_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_SP_MPEG2_L2_ISO,' \
  'http-get:*:video/x-ms-asf:DLNA.ORG_PN=MPEG4_P2_ASF_SP_G726,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_VGA_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_VGA_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_HEAAC_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_ATRAC3plus,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_ASP_AAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_ASP_AAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_ASP_AAC_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_ASP_MPEG1_L3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_ASP_MPEG1_L3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_ASP_MPEG1_L3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_ASP_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_ASP_AC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_ASP_AC3_ISO,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_L5_SO_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_L5_SO_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_L5_SO_HEAAC_MULT5,' \
  'http-get:*:video/x-ms-asf:DLNA.ORG_PN=MPEG4_P2_ASF_ASP_L5_SO_G726,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_L4_SO_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_L4_SO_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_ASP_L4_SO_HEAAC_MULT5,' \
  'http-get:*:video/x-ms-asf:DLNA.ORG_PN=MPEG4_P2_ASF_ASP_L4_SO_G726,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=MPEG4_H263_MP4_P0_L10_AAC_LTP,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=MPEG4_H263_3GPP_P0_L10_AMR_WBplus,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_CO_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_CO_AC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_CO_AC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_CO_MPEG2_L2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG4_P2_TS_CO_MPEG2_L2_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=MPEG4_P2_TS_CO_MPEG2_L2_ISO,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=MPEG4_P2_3GPP_SP_L0B_AAC,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=MPEG4_P2_3GPP_SP_L0B_AMR,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=MPEG4_H263_3GPP_P3_L10_AMR,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_MULT5,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_MULT5_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_HEAAC_L2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_HEAAC_L2_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_HEAAC_L2_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_MPEG1_L3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_MPEG1_L3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_MPEG1_L3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_AC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_MULT5,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_MULT5_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_MULT7,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_MULT7_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_AAC_LTP_MULT7_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_BSAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_SD_BSAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_SD_BSAC_ISO,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_AAC_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_HEAAC_L2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_MPEG1_L3,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_AC3,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_AAC_LTP,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_AAC_LTP_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_AAC_LTP_MULT7,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_ATRAC3plus,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L3L_SD_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L3L_SD_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L3_SD_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_BSAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_MULT5,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_MULT5_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_HEAAC_L2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_HEAAC_L2_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_HEAAC_L2_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_MPEG1_L3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_MPEG1_L3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_MPEG1_L3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_AC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_LTP,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_LTP_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_LTP_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_LTP_MULT5,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_LTP_MULT5_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_LTP_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_940,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_940_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF30_AAC_940_ISO,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_AAC_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_HEAAC_L2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_MPEG1_L3,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_AC3,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_AAC_LTP,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_AAC_LTP_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L2_CIF30_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_BSAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_BSAC_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_AAC_940,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AMR,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_MULT5,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_MULT5_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_HEAAC_L2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_HEAAC_L2_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_HEAAC_L2_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_MPEG1_L3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_MPEG1_L3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_MPEG1_L3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AC3_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_AC3_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_MULT5,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_MULT5_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_MULT7,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_MULT7_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_MP_HD_AAC_LTP_MULT7_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_540,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_540_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_540_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_LTP,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_LTP_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF15_AAC_LTP_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_BSAC,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_BL_CIF15_BSAC_T,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_BL_CIF15_BSAC_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_60_AC3,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AAC_520,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AAC_LTP,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AAC_LTP_520,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_BSAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L12_CIF15_HEAAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L1B_QCIF15_HEAAC,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_CIF30_AMR_WBplus,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_CIF15_AMR_WBplus,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_QCIF15_AAC,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_QCIF15_AAC_LTP,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_QCIF15_HEAAC,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_QCIF15_AMR_WBplus,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=AVC_3GPP_BL_QCIF15_AMR,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVMED_BASE,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVMED_FULL,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVMED_PRO,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVHIGH_FULL,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVHIGH_PRO,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVHM_BASE,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVSPLL_BASE,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVSPML_BASE,' \
  'http-get:*:video/x-ms-wmv:DLNA.ORG_PN=WMVSPML_MP3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=MPEG_TS_JP_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_60_AC3_T,' \
  'http-get:*:text/xml:SEC.COM_DIDLSIMAGE=1;SEC.COM_DIDLSAUDIO=1;SEC.COM_DIDLSVIDEO=1,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L12_CIF15_HEAACv2_350,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_HEAAC_350,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AAC_350,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L6_HEAAC_L2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_HP_HD_HEAAC_L2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_24_AC3,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_HP_HD_EAC3,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_MP_HD_EAC3,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_HP_HD_MPEG1_L3,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_MP_HD_MPEG1_L3,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAAC_L4,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAAC_L4,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_JP_AAC_T,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_HEAAC_L4,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_HP_HD_HEAAC_L4,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_MP_HD_HEAAC_L4,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L3_HEAACv2_L2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L0B_HEAACv2_L2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_H263_MP4_P0_L45_HEAACv2_L2,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAACv2_L2,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAACv2_L2,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HD_24_AC3_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HD_50_AC3_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HD_60_AC3_ISO,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF30_HEAACv2_L2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_HEAACv2_L2,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_HD_AC3_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_HD_EAC3_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_SD_AC3_ISO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAACv2_L3,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAACv2_L3,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAACv2_L4,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAACv2_L4,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_SD_EAC3_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_HD_EAC3_T,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_HP_SD_HEAACv2_L4,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_HP_HD_HEAACv2_L4,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_SD_EU,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=HEAAC_L2_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_SD_MPEG1_L2_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_HD_MPEG1_L2_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_SD_EAC3_ISO,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L1B_QCIF15_HEAACv2,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L12_CIF15_HEAACv2,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_SD_EU_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_60_AC3_X_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_50_AC3_X_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_24_AC3_X_T,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=HEAAC_MULT5_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_SD_EU_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HD_EU_ISO,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=AAC_MULT5_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_SD_HEAACv2_L4_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_HD_HEAACv2_L4_T,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAACv2_MULT5,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAACv2_MULT5,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=HEAAC_L3_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_NA_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_50_AC3,' \
  'http-get:*:audio/x-ms-wma:DLNA.ORG_PN=WMALSL_MULT5,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=AAC_ISO_192,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=AAC_ISO_192,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L5_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_SD_AAC_LC,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_SD_HEAACv2_L4_ISO,' \
  'http-get:*:video/mpeg:DLNA.ORG_PN=AVC_TS_HP_HD_HEAACv2_L4_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_SD_MPEG1_L2_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_HD_MPEG1_L2_T,' \
  'http-get:*:audio/x-ms-wma:DLNA.ORG_PN=WMAPRO,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAACv2_L2_320,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAACv2_L2_320,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAACv2_L2_128,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=HEAACv2_L2_128,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=MPEG4_P2_MP4_SP_L6_AAC,' \
  'http-get:*:video/3gpp:DLNA.ORG_PN=MPEG4_H263_MP4_P0_L10_AAC,' \
  'http-get:*:image/gif:DLNA.ORG_PN=GIF_LRG,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=HEAAC_L2_ISO_320,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=HEAAC_L2_ISO_128,' \
  'http-get:*:audio/mp4:DLNA.ORG_PN=HEAAC_L2_ISO_128,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=AAC_ISO_320,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_HP_HD_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L32_HD_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_L31_HD_AAC,' \
  'http-get:*:audio/x-ms-wma:DLNA.ORG_PN=WMALSL,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_SD_AC3_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HP_HD_AC3_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_50_AC3_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_24_AC3_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_24_LPCM_T,' \
  'http-get:*:audio/vnd.dlna.adts:DLNA.ORG_PN=AAC_ADTS_192,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_NA_T,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_EU,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_50_LPCM_T,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_HP_HD_AC3,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_MP_HD_AC3,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_EU_T,' \
  'http-get:*:audio/L16:DLNA.ORG_PN=LPCM_low,' \
  'http-get:*:video/x-ms-asf:DLNA.ORG_PN=VC1_ASF_AP_L1_WMA,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_HP_HD_AAC_MULT5,' \
  'http-get:*:video/x-matroska:DLNA.ORG_PN=AVC_MKV_MP_HD_AAC_MULT5,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_HP_HD_HEAAC_MULT7,' \
  'http-get:*:audio/3gpp:DLNA.ORG_PN=AAC_ISO,' \
  'http-get:*:video/vnd.dlna.mpeg-tts:DLNA.ORG_PN=AVC_TS_HD_60_LPCM_T,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_HD_1080i_AAC,' \
  'http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_MP_HD_720p_AAC,' \
  'http-get:*:audio/eac3:DLNA.ORG_PN=EAC3,' \
  'http-get:*:image/jpeg:*,' \
  'http-get:*:image/png:*,' \
  'http-get:*:image/bmp:*,' \
  'http-get:*:image/mpo:*,' \
  'http-get:*:audio/mpeg:*,' \
  'http-get:*:audio/x-ms-wma:*,' \
  'http-get:*:audio/mp4:*,' \
  'http-get:*:audio/x-m4a:*,' \
  'http-get:*:audio/3ga:*,' \
  'http-get:*:audio/ogg:*,' \
  'http-get:*:audio/x-wav:*,' \
  'http-get:*:audio/x-flac:*,' \
  'http-get:*:smi/caption:*,' \
  'http-get:*:video/x-msvideo:*,' \
  'http-get:*:video/x-ms-asf:*,' \
  'http-get:*:video/x-divx:*,' \
  'http-get:*:video/x-ms-wmv:*,' \
  'http-get:*:video/x-mkv:*,' \
  'http-get:*:video/mp4:*,' \
  'http-get:*:video/x-avi:*,' \
  'http-get:*:video/avi:*,' \
  'http-get:*:video/x-flv:*,' \
  'http-get:*:video/mpeg:*,' \
  'http-get:*:video/3gpp:*,' \
  'http-get:*:video/webm:*,' \
  'http-get:*:video/x-matroska:*,' \
  'http-get:*:image/gif:*,' \
  'http-get:*:audio/eac3:*,' \
  'http-get:*:application/vnd.ms-search:*,' \
  'http-get:*:application/vnd.ms-wpl:*,' \
  'http-get:*:application/x-ms-wmd:*,' \
  'http-get:*:application/x-ms-wmz:*,' \
  'http-get:*:application/x-shockwave-flash:*,' \
  'http-get:*:audio/3gpp2:*,' \
  'http-get:*:audio/aiff:*,' \
  'http-get:*:audio/basic:*,' \
  'http-get:*:audio/l8:*,' \
  'http-get:*:audio/mid:*,' \
  'http-get:*:audio/wav:*,' \
  'http-get:*:audio/x-matroska:*,' \
  'http-get:*:audio/x-mpegurl:*,' \
  'http-get:*:audio/x-ms-wax:*,' \
  'http-get:*:image/vnd.ms-photo:*,' \
  'http-get:*:video/3gpp2:*,' \
  'http-get:*:video/quicktime:*,' \
  'http-get:*:video/x-matroska-3d:*,' \
  'http-get:*:video/x-ms-wm:*,' \
  'http-get:*:video/x-ms-wmx:*,' \
  'http-get:*:video/x-ms-wvx:*,' \
  'http-get:*:audio/x-wavpack:*,' \
  'http-get:*:video/mp2t:*,' \
  'http-get:*:audio/x-ogg:*,' \
  'http-get:*:audio/ac3:*,' \
  'http-get:*:image/avif:*,' \
  'rtsp-rtp-udp:*:audio/L16:*,' \
  'rtsp-rtp-udp:*:audio/L8:*,' \
  'rtsp-rtp-udp:*:audio/mpeg:*,' \
  'rtsp-rtp-udp:*:audio/x-ms-wma:*,' \
  'rtsp-rtp-udp:*:video/x-ms-wmv:*,' \
  'rtsp-rtp-udp:*:audio/x-asf-pf:*'

  @staticmethod
  def retrieve_ips():
    iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
    class MIB_IPADDRROW(ctypes.Structure):
      _fields_=[('dwAddr', DWORD), ('dwIndex', DWORD), ('dwMask', DWORD), ('dwBCastAddr', DWORD), ('dwReasmSize', DWORD), ('unused', USHORT), ('wType', USHORT)]
    class MIB_IPADDRTABLE(ctypes.Structure):
      _fields_ = [('dwNumEntries', DWORD), ('table', MIB_IPADDRROW*0)]
    P_MIB_IPADDRTABLE = POINTER(MIB_IPADDRTABLE)
    s = ULONG(0)
    b = ctypes.create_string_buffer(s.value)
    while iphlpapi.GetIpAddrTable(b, ctypes.byref(s), False) == 122:
      b = ctypes.create_string_buffer(s.value)
    r = ctypes.cast(b, P_MIB_IPADDRTABLE).contents
    n = r.dwNumEntries
    t = ctypes.cast(ctypes.byref(r.table), POINTER(MIB_IPADDRROW * n)).contents
    return tuple(socket.inet_ntoa(e.dwAddr.to_bytes(4, 'little')) for e in t if e.wType & 1)

  def __init__(self, RendererIp='', RendererPort=8000, Minimize=False, FullScreen=False, WMPDMCHideMKV=False, TrustControler=False, SearchSubtitles=False, gapless=False, verbosity=0):
    self.verbosity = verbosity
    self.logger = log_event(verbosity)
    if RendererIp:
      self.Ip = RendererIp
    else:
      try:
        s = socket.socket(type=socket.SOCK_DGRAM)
        s.connect(('239.255.255.250', 1900))
        self.Ip = s.getsockname()[0]
        s.close()
      except:
        try:
          self.Ip = socket.gethostbyname(socket.gethostname())
        except:
          try:
            self.Ip = socket.gethostbyname(socket.getfqdn())
          except:
            self.Ip = '0.0.0.0'
            self.logger.log(LSTRINGS['ip_failure'], 0)
    if socket.inet_aton(self.Ip) != b'\x00\x00\x00\x00':
      self.Ips = (self.Ip,)
    else:
      self.Ips = self.retrieve_ips()
    self.Port = RendererPort
    self.Minimize = Minimize
    self.FullScreen = FullScreen
    self.full_screen = FullScreen
    self.WMPDMCHideMKV = WMPDMCHideMKV
    self.TrustControler = TrustControler
    self.SearchSubtitles = SearchSubtitles
    self.Gapless = gapless
    self.IPCmpvControlerInstance = IPCmpvControler(title_name=NAME + ':%s' % RendererPort , verbosity=verbosity)
    self.send_command(('set_property', 'force-media-title', " "))
    if gapless:
      self.send_command(('set_property', 'access-references', False))
      if gapless == 'p':
        self.send_command(('set_property', 'prefetch-playlist', True))
    self.is_search_manager_running = None
    self.is_request_manager_running = None
    self.is_events_manager_running = None
    self.mpv_shutdown_event = threading.Event()
    self.EventSubscriptions = []
    self.ActionsProcessed = 0
    self.ActionsReceived = 0
    self.ActionsCondition = threading.Condition()
    self.DescURL = 'http://%%s:%s/D_S' % self.Port
    root_xml = minidom.parseString(DLNARenderer.Device_SCPD)
    self.BaseURL = 'http://%%s:%s/' % self.Port
    self.Manufacturer = _XMLGetNodeText(root_xml.getElementsByTagName('manufacturer')[0])
    self.ModelName = _XMLGetNodeText(root_xml.getElementsByTagName('modelName')[0])
    self.FriendlyName = _XMLGetNodeText(root_xml.getElementsByTagName('friendlyName')[0])
    self.ModelDesc = _XMLGetNodeText(root_xml.getElementsByTagName('modelDescription')[0])
    self.ModelNumber = _XMLGetNodeText(root_xml.getElementsByTagName('modelNumber')[0])
    self.SerialNumber = _XMLGetNodeText(root_xml.getElementsByTagName('serialNumber')[0])
    self.UDN = _XMLGetNodeText(root_xml.getElementsByTagName('UDN')[0])
    self.IconURL = self.BaseURL + _XMLGetNodeText(root_xml.getElementsByTagName('icon')[-1].getElementsByTagName('url')[0])
    try:
      f = open(os.path.dirname(os.path.abspath(__file__)) + r"\icon.png",'rb')
      self.Icon = f.read()
      f.close()
    except:
      self.Icon = b''
    self.Services = []
    for node in root_xml.getElementsByTagName('service'):
      service = DLNAService()
      service.Type = _XMLGetNodeText(node.getElementsByTagName('serviceType')[0])
      service.Id = _XMLGetNodeText(node.getElementsByTagName('serviceId')[0])
      service.ControlURL = urllib.parse.urljoin(self.BaseURL, _XMLGetNodeText(node.getElementsByTagName('controlURL')[0]))
      service.SubscrEventURL = urllib.parse.urljoin(self.BaseURL, _XMLGetNodeText(node.getElementsByTagName('eventSubURL')[0]))
      service.DescURL = urllib.parse.urljoin(self.BaseURL, _XMLGetNodeText(node.getElementsByTagName('SCPDURL')[0]))
      root_s_xml = minidom.parseString((getattr(DLNARenderer, '%s_SCPD' % service.Id[23:])) % (() if service.Id[23:] != 'AVTransport' else ((DLNARenderer.AVTransport_SCPD_Gapless if self.Gapless else ''),)))
      for node_s in root_s_xml.getElementsByTagName('action'):
        action = DLNAAction()
        action.Name = _XMLGetNodeText(node_s.getElementsByTagName('name')[0])
        for node_a in node_s.getElementsByTagName('argument'):
          argument = DLNAArgument()
          argument.Name = _XMLGetNodeText(node_a.getElementsByTagName('name')[0])
          argument.Direction = _XMLGetNodeText(node_a.getElementsByTagName('direction')[0])
          statevar = _XMLGetNodeText(node_a.getElementsByTagName('relatedStateVariable')[0])
          node_sv = next(sv for sv in root_s_xml.getElementsByTagName('stateVariable') if sv.getElementsByTagName('name')[0].childNodes[0].data == statevar)
          if node_sv.getAttribute('sendEvents') == 'yes':
            argument.Event = True
          elif node_sv.getAttribute('sendEvents') == 'no':
            argument.Event = False
          argument.Type = _XMLGetNodeText(node_sv.getElementsByTagName('dataType')[0])
          try:
            node_sv_av = node_sv.getElementsByTagName('allowedValueList')[0]
            argument.AllowedValueList = *(_XMLGetNodeText(av) for av in node_sv_av.getElementsByTagName('allowedValue')),
          except:
            pass
          try:
            node_sv_ar = node_sv.getElementsByTagName('allowedValueRange')[0]
            argument.AllowedValueRange = (_XMLGetNodeText(node_sv_ar.getElementsByTagName('minimum')[0]), _XMLGetNodeText(node_sv_ar.getElementsByTagName('maximum')[0]))
          except:
            pass
          try:
            argument.DefaultValue = _XMLGetNodeText(node_sv.getElementsByTagName('defaultValue')[0])
          except:
            pass
          action.Arguments.append(argument)
        service.Actions.append(action)
      service.EventThroughLastChange = False
      try:
        node_sv = next(sv for sv in root_s_xml.getElementsByTagName('stateVariable') if sv.getElementsByTagName('name')[0].childNodes[0].data.upper() == 'LastChange'.upper())
        if node_sv.getAttribute('sendEvents') == 'yes':
          service.EventThroughLastChange = True
      except:
        pass
      self.Services.append(service)
    self.TransportState = "NO_MEDIA_PRESENT"
    self.Mute = "0"
    self.Volume = "0"
    self.AVTransportURI = ""
    self.AVTransportURIMetaData = ""
    self.RelativeTimePosition = "0:00:00"
    self.CurrentMediaDuration = "0:00:00"
    self.LoadfileOptions = ""
    self.NextAVTransportURI = ""
    self.NextAVTransportURIMetaData = ""
    self.NextLoadfileOptions = ""

  def send_advertisement(self, alive):
    msg = 'NOTIFY * HTTP/1.1\r\n' \
    'Host: 239.255.255.250:1900\r\n' \
    'Cache-control: max-age=1800\r\n' \
    'Location: ' + self.DescURL + '\r\n' \
    'NT: ##NT##\r\n' \
    'NTS: ssdp:' + ('alive' if alive else 'byebye') + '\r\n' \
    'Server: DLNAmpvRenderer\r\n' \
    'USN: ' + UDN + '##NT##\r\n' \
    '\r\n'
    for ip in self.Ips:
      try:
        sock = socket.socket(type=socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.bind((ip, 0))
        sock.sendto((msg % ip).replace('##NT##', '::upnp:rootdevice').encode('ISO-8859-1'), ('239.255.255.250', 1900))
        sock.sendto((msg % ip).replace('##NT##', '').encode('ISO-8859-1'), ('239.255.255.250', 1900))
        sock.sendto((msg % ip).replace('##NT##', '::urn:schemas-upnp-org:device:MediaRenderer:1').encode('ISO-8859-1'), ('239.255.255.250', 1900))
        sock.sendto((msg % ip).replace('##NT##', '::urn:schemas-upnp-org:service:RenderingControl:1').encode('ISO-8859-1'), ('239.255.255.250', 1900))
        sock.sendto((msg % ip).replace('##NT##', '::urn:schemas-upnp-org:service:ConnectionManager:1').encode('ISO-8859-1'), ('239.255.255.250', 1900))
        sock.sendto((msg % ip).replace('##NT##', '::urn:schemas-upnp-org:service:AVTransport:1').encode('ISO-8859-1'), ('239.255.255.250', 1900))
        sock.close()
        self.logger.log('Envoi, sur l\'interface %s, du message de publicité: %s' % (ip, ('alive' if alive else 'byebye')), 2)
      except:
        self.logger.log('Échec de l\'envoi, sur l\'interface %s, du message de publicité: %s' % (ip, ('alive' if alive else 'byebye')), 1)

  def _start_search_manager(self):
    try:
      with DLNASearchServer(self, self.verbosity) as self.DLNASearchManager:
        self.DLNASearchManager.serve_forever()
    except:
      self.logger.log('Échec du démarrage de l\'écoute, sur l\'interface %s, des messages de recherche de renderer' % self.Ip, 1)
    self.is_search_manager_running = None

  def _shutdown_search_manager(self):
    if self.is_search_manager_running:
      try:
        self.DLNASearchManager.shutdown()
      except:
        pass
    self.is_search_manager_running = False

  def start_search_management(self):
    if self.is_search_manager_running:
      self.logger.log('Écoute des messages de recherche de renderer déjà activée', 1)
    else:
      self.is_search_manager_running = True
      self.logger.log('Démarrage de l\'écoute, sur l\'interface %s, des messages de recherche de renderer' % self.Ip, 1)
      manager_thread = threading.Thread(target=self._start_search_manager)
      manager_thread.start()

  def stop_search_management(self):
    if self.is_search_manager_running:
      self.logger.log('Fin de l\'écoute des messages de recherche de renderer', 1)
      self._shutdown_search_manager()

  def _start_request_manager(self):
    DLNARequestBoundHandler = partial(DLNARequestHandler, renderer=self)
    try:
      with DLNARequestServer((self.Ip, self.Port), DLNARequestBoundHandler, verbosity=self.verbosity) as self.DLNARequestManager:
        self.DLNARequestManager.serve_forever()
    except:
      while self.IPCmpvControlerInstance.Pipe_handle == None and self.IPCmpvControlerInstance.Cmd_buffer[0] != "quit":
        time.sleep(0.1)
      self.mpv_shutdown_event.set()
      self.logger.log(LSTRINGS['request_failure'] % (self.Ip, self.Port), 0)
    finally:
      self.is_request_manager_running = None

  def _shutdown_request_manager(self):
    if self.is_request_manager_running:
      try:
        self.DLNARequestManager.shutdown()
      except:
        pass
      self.is_request_manager_running = False
      with self.ActionsCondition:
        self.ActionsCondition.notify_all()

  def start_request_management(self):
    if self.is_request_manager_running:
      self.logger.log('Écoute des requêtes déjà activée', 1)
    else:
      self.is_request_manager_running = True
      self.logger.log('Démarrage de l\'écoute des requêtes à l\'adresse %s:%s' % (self.Ip, self.Port), 1)
      manager_thread = threading.Thread(target=self._start_request_manager)
      manager_thread.start()

  def stop_request_management(self):
    if self.is_request_manager_running:
      self.logger.log('Fin de l\'écoute des requêtes', 1)
      self._shutdown_request_manager()

  def send_command(self, commands):
    self.IPCmpvControlerInstance.Cmd_buffer.append(commands)
    kernel32.SetEvent(self.IPCmpvControlerInstance.Cmd_Event)

  def events_add(self, service, events):
    for event_sub in self.EventSubscriptions:
      if event_sub.End_time > 0 and service.lower() in event_sub.Service.Id.lower():
        event_sub.Events.append(events)
        event_sub.EventEvent.set()

  def _events_manager(self):
    while self.is_events_manager_running:
      self.IPCmpvControlerInstance.Player_event_event.clear()
      if self.IPCmpvControlerInstance.Msg_buffer[0] == "quit":
        self.mpv_shutdown_event.set()
      while len(self.IPCmpvControlerInstance.Player_events) > 0:
        event = self.IPCmpvControlerInstance.Player_events.pop(0)
        if event[0] == 'RelativeTimePosition':
          self.RelativeTimePosition = event[1] if event[1] else "0:00:00"
        elif event[0] == 'CurrentMediaDuration':
          self.CurrentMediaDuration = event[1] if event[1] else "0:00:00"
          self.events_add('AVTransport', (('CurrentMediaDuration', self.CurrentMediaDuration),('CurrentTrackDuration', self.CurrentMediaDuration)))
        elif event[0] == 'TransportState':
          self.TransportState = event[1].upper().replace("STARTING", "TRANSITIONING")
          if self.TransportState == "STOPPED":
            self.full_screen = self.FullScreen
            self.send_command(('set_property', 'script-opts', 'osc-visibility=never'))
            if self.Minimize:
              self.send_command(('set_property', 'window-minimized', True))
          elif self.TransportState in ('PLAYING', 'PAUSED_PLAYBACK'):
            self.send_command(('set_property', 'script-opts', 'osc-visibility=auto'))
            if self.Minimize:
              self.send_command(('set_property', 'window-minimized', False))
            if self.full_screen:
              self.full_screen = False
              self.send_command(('set_property', 'fullscreen', True))
          if not self.Gapless or event[1].upper() != "STARTING" or not self.NextAVTransportURI:
            self.events_add('AVTransport', (('TransportState', self.TransportState), ('CurrentTransportActions', {'TRANSITIONING': "Stop", 'STOPPED': "Play,Seek",'PAUSED_PLAYBACK': "Play,Stop,Seek" ,'PLAYING': "Pause,Stop,Seek"}.get(self.TransportState, ""))))
        elif event[0] == 'TransportStatus' and event[1].upper() == "ERROR_OCCURRED":
          self.events_add('AVTransport', (('TransportStatus', "ERROR_OCCURRED"),))
          self.events_add('AVTransport', (('TransportStatus', "OK"),))
        elif self.Gapless and event[0] == 'Playlist' and event[1] == '1':
          self.events_add('AVTransport', (('TransportState', "PLAYING"), ('CurrentTransportActions',  "Pause,Stop,Seek")))
          self.send_command(('playlist-remove', 0))
          self.AVTransportURI = self.NextAVTransportURI
          self.AVTransportURIMetaData = self.NextAVTransportURIMetaData
          self.LoadfileOptions = self.NextLoadfileOptions
          self.NextAVTransportURI = ""
          self.NextAVTransportURIMetaData = ""
          self.NextLoadfileOptions = ""
          self.events_add('AVTransport', (('AVTransportURI', self.AVTransportURI), ('AVTransportURIMetaData', self.AVTransportURIMetaData), ('CurrentTrackMetaData', self.AVTransportURIMetaData), ('CurrentTrackURI', self.AVTransportURI), ('NextAVTransportURI', self.NextAVTransportURI), ('NextAVTransportURIMetaData', self.NextAVTransportURIMetaData)))
          self.logger.log(LSTRINGS['next_current'], 0)
        elif event[0] == 'Mute':
          self.Mute = "1" if event[1] else "0"
          self.events_add('RenderingControl', (('Mute channel="Master"', self.Mute),))
        elif event[0] == 'Volume':
          self.Volume = str(event[1])
          self.events_add('RenderingControl', (('Volume channel="Master"', self.Volume),))
      if self.is_events_manager_running:
        self.IPCmpvControlerInstance.Player_event_event.wait()

  def _shutdown_events_manager(self):
    self.is_events_manager_running = False
    self.IPCmpvControlerInstance.Player_event_event.set()
    for event_sub in self.EventSubscriptions:
      event_sub.stop_event_management()

  def start_events_management(self):
    if self.is_events_manager_running:
      self.logger.log('Gestion des événements déjà activée', 1)
    else:
      self.is_events_manager_running = True
      self.logger.log('Démarrage de la gestion des événements', 1)
      manager_thread = threading.Thread(target=self._events_manager)
      manager_thread.start()

  def stop_events_management(self):
    if self.is_events_manager_running:
      self.logger.log('Fin de la gestion des événements', 1)
      self._shutdown_events_manager()

  def _process_action(self, action_id, servi, acti, args, agent):
    service = next((serv for serv in self.Services if serv.Id.lower() == ('urn:upnp-org:serviceId:' + servi).lower()), None)
    if not service:
      return '400', None
    action = next((act for act in service.Actions if act.Name.lower() == acti.lower()), None)
    if not action:
      return '401', None
    in_args = dict((arg.Name.lower(), arg.DefaultValue) for arg in action.Arguments if arg.Direction.lower() == 'in')
    for prop_name, prop_value in args:
      if not prop_name.lower() in in_args:
        return '402', None
      in_args[prop_name.lower()] = prop_value
    for prop_name in in_args:
      if in_args[prop_name] == None:
        return '402', None
    out_args = dict((arg.Name, arg.DefaultValue) for arg in action.Arguments if arg.Direction.lower() == 'out')
    with self.ActionsCondition:
      while action_id > self.ActionsProcessed and self.is_request_manager_running:
        self.ActionsCondition.wait()
    if not self.is_request_manager_running:
      return '701', None
    self.logger.log('Début du traitement de l\'action %d %s-%s' % (action_id, servi, acti), 2)
    if acti.lower() == 'GetProtocolInfo'.lower():
      out_args['Source'] = ""
      if not "Microsoft".lower() in agent.lower() or not self.WMPDMCHideMKV:
        out_args['Sink'] = DLNARenderer.Sink
      else:
        out_args['Sink'] = DLNARenderer.Sink.replace(',http-get:*:video/x-matroska:*','')
    elif acti.lower() == 'SetAVTransportURI'.lower() or (acti.lower() == 'SetNextAVTransportURI'.lower() and self.Gapless):
      is_next = acti.lower() == 'SetNextAVTransportURI'.lower()
      if self.NextAVTransportURI:
        self.send_command(('playlist-remove', 1))
        self.NextAVTransportURI = ""
        self.NextAVTransportURIMetaData = ""
        self.NextLoadfileOptions = ""
      if not is_next:
        prev_transp_state = self.TransportState
        self.TransportState = "TRANSITIONING"
        self.events_add('AVTransport', (('TransportState', "TRANSITIONING"), ('CurrentTransportActions', "Stop")))
      uri = None
      protocol_info = ''
      title = ''
      upnp_class = ''
      s_protocol_info = ''
      caption_info = ''
      caption_type = ''
      try:
        didl_root = minidom.parseString(in_args['NextURIMetaData'.lower() if is_next else 'CurrentURIMetaData'.lower()])
        node = None
        for ch_node in didl_root.documentElement.childNodes:
          if ch_node.nodeType == ch_node.ELEMENT_NODE:
            if ch_node.localName.lower() == 'item':
              node = ch_node
              break
        for ch_node in node.childNodes:
          if ch_node.nodeType == ch_node.ELEMENT_NODE:
            if ch_node.localName.lower() == 'title':
              title = _XMLGetNodeText(ch_node)[:501]
            elif ch_node.localName.lower() == 'res':
              for att in ch_node.attributes.itemsNS():
                if att[0][1].lower() == 'protocolinfo':
                  if not uri:
                    if not 'DLNA.ORG_CI=' in att[1].upper():
                      uri = _XMLGetNodeText(ch_node)
                      protocol_info = att[1]
                    else:
                      if att[1].upper().partition('DLNA.ORG_CI=')[2].split(';')[0] == 0:
                        uri = _XMLGetNodeText(ch_node)
                        protocol_info = att[1]
                  if not s_protocol_info and in_args['NextURI'.lower() if is_next else 'CurrentURI'.lower()] == _XMLGetNodeText(ch_node):
                    s_protocol_info = att[1]
                elif not caption_info and att[0][1].lower() == 'subtitlefileuri':
                  caption_info = att[1]
                elif not caption_type and att[0][1].lower() == 'subtitlefiletype':
                  caption_type = att[1]
            elif ch_node.localName.lower() == 'class':
              upnp_class = _XMLGetNodeText(ch_node)
            elif ch_node.localName.lower().startswith('captioninfo'):
              caption_info = _XMLGetNodeText(ch_node)
              caption_type = next((att_v for (att_n, att_v) in ch_node.attributes.itemsNS() if att_n[1].lower() == 'type'), '')
      except:
        uri = None
      if not uri:
        uri = in_args['NextURI'.lower() if is_next else 'CurrentURI'.lower()]
        protocol_info = s_protocol_info
      rep = None
      server = ''
      accept_range = True
      if uri:
        if self.TrustControler:
          rep = True
        elif r'://' in uri:
          rep = _open_url(uri, method='HEAD', test_range=True)
          if rep:
            server = rep.getheader('Server', '')
            if rep.getheader('Accept-Ranges'):
              if rep.getheader('Accept-Ranges').lower() == 'none':
                accept_range = False
            elif rep.status != 206:
              accept_range = False
        else:
          rep = os.path.isfile(uri)
      if not rep:
        if not is_next:
          self.events_add('AVTransport', (('TransportStatus', "ERROR_OCCURRED"),))
          self.events_add('AVTransport', (('TransportStatus', "OK"),))
          self.TransportState = prev_transp_state
          self.IPCmpvControlerInstance.Player_events.append(('TransportState', prev_transp_state))
          self.IPCmpvControlerInstance.Player_event_event.set()
          return '716', None
        elif not uri:
          return '200', out_args
        else:
          return '716', None
      title = title or ' '
      load_opt = "force-media-title=%%%d%%%s" % (len(title.encode('utf-8')), title)
      if is_next:
        self.NextAVTransportURI = uri
      else:
        self.AVTransportURI = uri
      if rep == True:
        sub_uri = caption_info
      else:
        sub_uri = rep.getheader('CaptionInfo.sec', caption_info)
        rep.close()
      rep = None
      if sub_uri and not self.TrustControler:
        if r'://' in uri:
          rep = _open_url(sub_uri, method='HEAD')
        else:
          rep = os.path.isfile(sub_uri)
        if not rep:
          sub_uri = ''
        elif rep != True:
          rep.close()
      if self.SearchSubtitles and 'object.item.videoItem'.lower() in upnp_class.lower() and not sub_uri and r'://' in uri and not 'Microsoft-HTTPAPI'.lower() in server.lower() and not "BubbleUPnP".lower() in server.lower():
        uri_name = uri.rsplit('.', 1)[0]
        for sub_ext in ('.ttxt', '.txt', '.smi', '.srt', '.sub', '.ssa', '.ass', '.vtt'):
          rep = _open_url(uri_name + sub_ext, method='HEAD', timeout=2)
          if rep:
            sub_uri = uri_name + sub_ext
            caption_type = sub_ext
            rep.close()
            break
      uri_metadata = '<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/" xmlns:sec="http://www.sec.co.kr/"><item><dc:title>%s</dc:title><upnp:class>%s</upnp:class><res protocolInfo="%s">%s</res>%s</item></DIDL-Lite>' % (html.escape(title), upnp_class, html.escape(protocol_info), html.escape(uri), '<sec:CaptionInfoEx sec:type="%s">%s</sec:CaptionInfoEx>' %(html.escape(caption_type), html.escape(sub_uri)) if sub_uri else '')
      if is_next:
        self.NextAVTransportURIMetaData = uri_metadata
      else:
        self.AVTransportURIMetaData = uri_metadata
      if is_next:
        self.events_add('AVTransport', (('NextAVTransportURI', self.NextAVTransportURI), ('NextAVTransportURIMetaData', self.NextAVTransportURIMetaData)))
      else:
        self.events_add('AVTransport', (('AVTransportURI', self.AVTransportURI), ('AVTransportURIMetaData', self.AVTransportURIMetaData), ('CurrentTrackMetaData', self.AVTransportURIMetaData), ('CurrentTrackURI', self.AVTransportURI)))
      if 'MDEServer'.lower() in uri.lower():
        if 'DLNA.ORG_CI' in uri_metadata and not 'DLNA.ORG_CI=0' in uri_metadata:
          load_opt += ",stream-lavf-o=seekable=0"
      elif not accept_range:
        load_opt += ",stream-lavf-o=seekable=0"
      if sub_uri:
        load_opt += ",sub-files=%%%d%%%s"% (len(sub_uri.encode('utf-8')), sub_uri)
      if not is_next:
        self.LoadfileOptions = load_opt
        if prev_transp_state == "TRANSITIONING":
          self.send_command(('stop',))
        if self.IPCmpvControlerInstance.Player_status.upper() in ("NO_MEDIA_PRESENT", "STOPPED") and prev_transp_state in ("NO_MEDIA_PRESENT", "STOPPED"):
          self.TransportState = "STOPPED"
          self.RelativeTimePosition = "0:00:00"
          self.CurrentMediaDuration = "0:00:00"
          self.IPCmpvControlerInstance.Player_events.append(('TransportState', "STOPPED"))
          self.events_add('AVTransport', (('CurrentMediaDuration', "0:00:00"), ('CurrentTrackDuration', "0:00:00")))
          self.IPCmpvControlerInstance.Player_event_event.set()
        else:
          self.send_command(('loadfile', self.AVTransportURI, 'replace', self.LoadfileOptions))
          self.send_command(('set_property', 'pause', False))
        self.logger.log(LSTRINGS['current_content'] % (LSTRINGS['video'] if 'video' in upnp_class.lower() else LSTRINGS['audio'] if 'audio' in upnp_class.lower() else LSTRINGS['image'] if 'image' in upnp_class.lower() else '', title, self.AVTransportURI + ((' + ' + sub_uri) if sub_uri else '')), 0)
      else:
        self.NextLoadfileOptions = load_opt
        self.send_command(('loadfile', self.NextAVTransportURI, 'append', self.NextLoadfileOptions))
        self.logger.log(LSTRINGS['next_content'] % ('vidéo' if 'video' in upnp_class.lower() else 'audio' if 'audio' in upnp_class.lower() else 'image' if 'image' in upnp_class.lower() else '', title, self.NextAVTransportURI + ((' + ' + sub_uri) if sub_uri else '')), 0)
    elif acti.lower() == 'Play'.lower():
      if self.TransportState == "NO_MEDIA_PRESENT":
        return '701', None
      if self.IPCmpvControlerInstance.Player_status.upper() in ("STOPPED", "NO_MEDIA_PRESENT"):
        self.send_command(('loadfile', self.AVTransportURI, 'replace', self.LoadfileOptions))
        self.send_command(('set_property', 'script-opts', 'osc-visibility=auto'))
        if self.Minimize:
          self.send_command(('set_property', 'window-minimized', False))
      self.send_command(('set_property', 'pause', False))
    elif acti.lower() == 'Pause'.lower():
      if self.TransportState == "NO_MEDIA_PRESENT":
        return '701', None
      self.send_command(('set_property', 'pause', True))
    elif acti.lower() == 'Stop'.lower():
      if self.TransportState in ("PLAYING", "PAUSED_PLAYBACK", "TRANSITIONING"):
        self.send_command(('set_property', 'script-opts', 'osc-visibility=never'))
        self.send_command(('stop',))
        if self.Minimize:
          self.send_command(('set_property', 'window-minimized', True))
    elif acti.lower() == 'Seek'.lower():
      if self.TransportState == "NO_MEDIA_PRESENT":
        return '701', None
      if not in_args['unit'].upper() in ("REL_TIME", "ABS_TIME"):
        return '701', None
      self.send_command(('seek', in_args['target'], 'absolute'))
    elif acti.lower() == 'GetPositionInfo'.lower():
      if self.TransportState == "NO_MEDIA_PRESENT":
        out_args = {'Track': '0', 'TrackDuration': '0:00:00', 'TrackMetaData': '', 'TrackURI': '', 'RelTime': '0:00:00', 'AbsTime': '0:00:00', 'RelCount': '2147483647', 'AbsCount': '2147483647'}
      else:
        out_args['Track'] = "1"
        out_args['TrackDuration'] = self.CurrentMediaDuration
        out_args['TrackMetaData'] = self.AVTransportURIMetaData
        out_args['TrackURI'] = self.AVTransportURI
        out_args['RelTime'] = self.RelativeTimePosition
        out_args['AbsTime'] = self.RelativeTimePosition
        out_args['RelCount'] = "2147483647"
        out_args['AbsCount'] = "2147483647"
    elif acti.lower() == 'GetMediaInfo'.lower():
      out_args['NrTracks'] = "1" if self.TransportState != "NO_MEDIA_PRESENT" else "0"
      out_args['MediaDuration'] = self.CurrentMediaDuration
      out_args['CurrentURI'] = self.AVTransportURI
      out_args['CurrentURIMetaData'] = self.AVTransportURIMetaData
      out_args['NextURI'] = self.NextAVTransportURI
      out_args['NextURIMetaData'] = self.NextAVTransportURIMetaData
      out_args['PlayMedium'] = "NETWORK,NONE"
      out_args['RecordMedium'] = "NOT_IMPLEMENTED"
      out_args['WriteStatus'] = "NOT_IMPLEMENTED"
    elif acti.lower() == 'GetTransportInfo'.lower():
      out_args['CurrentTransportState'] = self.TransportState
      out_args['CurrentTransportStatus'] = 'OK'
      out_args['CurrentSpeed'] = '1'
    elif acti.lower() == 'GetMute'.lower():
      out_args['CurrentMute'] = self.Mute
    elif acti.lower() == 'GetVolume'.lower():
      out_args['CurrentVolume'] = self.Volume
    elif acti.lower() == 'SetMute'.lower():
      self.send_command(('set_property', 'mute', True if in_args['DesiredMute'.lower()] == "1" else False))
    elif acti.lower() == 'SetVolume'.lower():
      self.send_command(('set_property', 'volume', int(float(in_args['DesiredVolume'.lower()]))))
    elif acti.lower() == 'GetCurrentTransportActions'.lower():
      out_args['Actions'] = {'TRANSITIONING': "Stop", 'STOPPED': "Play,Seek",'PAUSED_PLAYBACK': "Play,Stop,Seek" ,'PLAYING': "Pause,Stop,Seek"}.get(self.TransportState, "")
    else:
      return '401', None
    if out_args == None:
      return '701', None
    else:
      return '200', out_args

  def process_action(self, servi, acti, args, agent):
    with self.ActionsCondition:
      action_id = self.ActionsReceived
      self.ActionsReceived += 1
    self.logger.log('Mise en queue de l\'action %d %s-%s' % (action_id, servi, acti), 2)
    try:
      res, out_args = self._process_action(action_id, servi, acti, args, agent)
    except:
      res = '701'
      out_args = None
    if res == '200':
      self.logger.log('Succès du traitement de l\'action %d %s-%s' % (action_id, servi, acti), 1)
    else:
      self.logger.log('Échec du traitement de l\'action %d %s-%s - code %s' % (action_id, servi, acti, res), 1)
    with self.ActionsCondition:
      self.ActionsProcessed += 1
      self.ActionsCondition.notify_all()
    return res, out_args

  def start(self):
    if not self.Ip:
      self.mpv_shutdown_event.set()
      return
    self.IPCmpvControlerInstance.start()
    if self.Minimize:
      self.send_command(('set_property', 'window-minimized', True))
    self.start_events_management()
    self.start_request_management()
    self.start_search_management()
    self.send_advertisement(True)
    self.send_advertisement(True)

  def stop(self):
    self.send_command(('stop',))
    self.send_advertisement(False)
    self.send_advertisement(False)
    self.stop_search_management()
    self.stop_request_management()
    self.stop_events_management()
    self.IPCmpvControlerInstance.stop()


if __name__ == '__main__':

  print('DLNAmpvRenderer v1.3.1 (https://github.com/PCigales/DLNAmpvRenderer)    Copyright © 2022 PCigales')
  print(LSTRINGS['license'])
  print('')

  formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=50, width=119)
  CustomArgumentParser = partial(argparse.ArgumentParser, formatter_class=formatter, add_help=False)
  parser = CustomArgumentParser()
  parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help=LSTRINGS['help'])
  parser.add_argument('--bind', '-b', metavar='RENDERER_IP', help=LSTRINGS['parser_ip'], nargs='?', const='0.0.0.0', default='')
  parser.add_argument('--port', '-p', metavar='RENDERER_TCP_PORT', help=LSTRINGS['parser_port'], type=int, default=8000)
  parser.add_argument('--name', '-n', metavar='RENDERER_NAME', help=LSTRINGS['parser_name'], default='DLNAmpvRenderer')
  parser.add_argument('--minimize', '-m', help=LSTRINGS['parser_minimized'], action='store_true')
  parser.add_argument('--fullscreen', '-f', help=LSTRINGS['parser_fullscreen'], action='store_true')
  parser.add_argument('--wmpdmc_no_mkv', '-w', help=LSTRINGS['parser_mkv'], action='store_true')
  parser.add_argument('--trust_controler', '-t', help=LSTRINGS['parser_trust'], action='store_true')
  parser.add_argument('--search_subtitles', '-s', help=LSTRINGS['parser_subtitles'], action='store_true')
  parser.add_argument('--gapless', '-g', help=LSTRINGS['parser_gapless'], nargs='?', const='g', default='')
  parser.add_argument('--verbosity', '-v', metavar='VERBOSE', help=LSTRINGS['parser_verbosity'], type=int, choices=[0, 1, 2], default=0)

  args = parser.parse_args()
  if args.name.strip() and args.name != 'DLNAmpvRenderer':
    NAME = args.name
    UDN = 'uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, args.name))
    DLNARenderer.Device_SCPD = DLNARenderer.Device_SCPD.replace('DLNAmpvRenderer', html.escape(NAME)).replace('uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'DLNAmpvRenderer')), UDN)
  Renderer = DLNARenderer(args.bind, args.port, args.minimize, args.fullscreen, args.wmpdmc_no_mkv, args.trust_controler, args.search_subtitles, args.gapless, args.verbosity)
  print(LSTRINGS['keyboard_s'])
  print(LSTRINGS['keyboard_m'] % (LSTRINGS['enabled'] if Renderer.Minimize else LSTRINGS['disabled']))
  print(LSTRINGS['keyboard_f'] % (LSTRINGS['enabled'] if Renderer.FullScreen else LSTRINGS['disabled']))
  Renderer.start()
  k = b''
  while not Renderer.mpv_shutdown_event.is_set() and k != b'S':
    while msvcrt.kbhit() and k != b'S':
      k = msvcrt.getch()
      if k == b'\xe0':
        k = k + msvcrt.getch()
        k = b''
        continue
      else:
        k = k.upper()
      if k == b'M':
        Renderer.Minimize = not Renderer.Minimize
        if Renderer.TransportState in ("NO_MEDIA_PRESENT", "STOPPED"):
          Renderer.send_command(('set_property', 'window-minimized', Renderer.Minimize))
        print(LSTRINGS['mode_m'] % (LSTRINGS['enabled'] if Renderer.Minimize else LSTRINGS['disabled']))
      elif k == b'F':
        Renderer.FullScreen = not Renderer.FullScreen
        Renderer.full_screen = Renderer.FullScreen
        print(LSTRINGS['mode_f'] % (LSTRINGS['enabled'] if Renderer.FullScreen else LSTRINGS['disabled']))
    if k != b'S':
      Renderer.mpv_shutdown_event.wait(0.5)
  Renderer.stop()