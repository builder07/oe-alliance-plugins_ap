from Screens.Screen import Screen
from Components.ConfigList import ConfigListScreen, ConfigList
from Components.config import config, ConfigSubsection, getConfigListEntry, ConfigSelection, ConfigIP, ConfigInteger
from Components.config import ConfigText, ConfigYesNo, NoSave, ConfigPassword, ConfigNothing, ConfigSequence
from Components.ActionMap import ActionMap
from Screens.MessageBox import MessageBox
from Screens.Standby import TryQuitMainloop
from Components.Sources.StaticText import StaticText
from Plugins.Plugin import PluginDescriptor
from Tools.Directories import fileExists
from math import pow as math_pow
from Components.Network import iNetwork
from Components.PluginComponent import plugins
from Components.Console import Console
from os import path as os_path, system as os_system, listdir, makedirs, access, R_OK
from Tools.Directories import resolveFilename, SCOPE_PLUGINS
from enigma import getDesktop, eTimer
from boxbranding import getBoxType, getMachineBuild
from Components.Label import Label
import subprocess
from time import sleep

def run_command(command):
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    for line in iter(p.stdout.readline, ''):
        if line:
            yield line

    while p.poll() is None:
        sleep(0.1)

    err = p.stdout.read()
    if p.returncode != 0:
        print 'Error: ' + str(err)
    return


debug_msg_on = False

def printDebugMsg(msg):
    global debug_msg_on
    if debug_msg_on:
        print '[Wireless Access Point] ', msg


class fixedValue():

    def __init__(self, value = ''):
        self.value = value


HOSTAPD_CONF = '/etc/hostapd.conf'
APINFO_1 = ''
APINFO_2 = ''
APINFO_ERR = ''
pAP = ConfigSubsection()
pAP.showplugin = ConfigYesNo(default=False)
pAP.useap = ConfigYesNo(default=False)
pAP.setupmode = ConfigSelection(default='preset', choices=[('preset', 'Preset:      SSID = OpenFIX      PWD = 12345678'), ('simple', 'Simple'), ('advanced', 'Advanced')])
pAP.bridge = fixedValue(value='br0')
pAP.driver = fixedValue(value='nl80211')
pAP.wirelessmode = ConfigSelection(default=' --ieee80211ac', choices=[(' --ieee80211ac', _('802.11ac mode (fastest)')), (' --ieee80211n', _('802.11n mode (fast)')), (' ', _('b+g mode (compatible with old stuff)'))])
pAP.band = ConfigSelection(default=' --freq-band 2.4', choices=[(' --freq-band 2.4', _('2.4 GHz')), (' --freq-band 5', _('5 GHz'))])
pAP.htcaps = ConfigSelection(default=' --ht_capab [HT40+]', choices=[(' --ht_capab [HT40+]', _('20 MHz and 40 MHz -2nd channel above the 1st channel')),
 (' --ht_capab [HT40-]', _('20 MHz and 40 MHz -2nd channel below the 1st channel')),
 (' ', _('20MHz')),
 (' --ht_capab [SHORT-GI-20][SHORT-GI-40][HT40]', _('short guard interval 40 Mhz'))])
pAP.hidden = ConfigSelection(default=' ', choices=[(' ', _('no')), (' --hidden', _('yes'))])
pAP.channel = ConfigSelection(default='1', choices=[('1', '1'),
 ('2', '2'),
 ('3', '3'),
 ('4', '4'),
 ('5', '5'),
 ('6', '6'),
 ('7', '7'),
 ('8', '8'),
 ('9', '9'),
 ('10', '10'),
 ('11', '11'),
 ('12', '12'),
 ('13', '13')])
pAP.channel5 = ConfigSelection(default='36', choices=[('36', '36'),
 ('40', '40'),
 ('44', '44'),
 ('48', '48'),
 ('52', '52'),
 ('56', '56'),
 ('60', '60'),
 ('64', '64'),
 ('100', '100'),
 ('110', '110')])
pAP.ssid = ConfigText(default='OpenFIX', visible_width=50, fixed_size=False)
pAP.country = ConfigSelection(default=' --country BL', choices=[(' --country BL', _('EUrope')),
 (' --country KR', _('Asia')),
 (' --country NZ', _('South Cross')),
 (' --country GH', _('Africa')),
 (' --country US', _('North America')),
 (' --country AR', _('South America'))])
pAP.multiple = ConfigYesNo(default=False)
pAP.encrypt = ConfigYesNo(default=True)
pAP.method = ConfigSelection(default=' -w 1+2', choices=[(' -w 1', _('WPA')), (' -w 2', _('WPA2')), (' -w 1+2', _('WPA/WPA2'))])
pAP.beacon = ConfigInteger(default=100, limits=(15, 65535))
pAP.rts_threshold = ConfigInteger(default=2347, limits=(0, 2347))
pAP.fragm_threshold = ConfigInteger(default=2346, limits=(256, 2346))
pAP.preamble = ConfigSelection(default='0', choices=[('0', 'Long'), ('1', 'Short')])
pAP.ignore_broadcast_ssid = ConfigSelection(default='0', choices=[('0', _('disabled')), ('1', _('enabled'))])
pAP.wep = ConfigYesNo(default=False)
pAP.wep_default_key = fixedValue(value='0')
pAP.wepType = ConfigSelection(default='64', choices=[('64', _('Enable 64 bit (Input 10 hex keys)')), ('128', _('Enable 128 bit (Input 26 hex keys)'))])
pAP.wep_key0 = ConfigPassword(default='', visible_width=50, fixed_size=False)
pAP.wpa = ConfigSelection(default='3', choices=[('0', _('not set')),
 ('1', _('WPA')),
 ('2', _('WPA2')),
 ('3', _('WPA/WPA2'))])
pAP.wpa_passphrase = ConfigText(default='12345678', visible_width=50, fixed_size=False)
pAP.wpagrouprekey = ConfigInteger(default=600, limits=(0, 3600))
pAP.wpa_key_mgmt = fixedValue(value='WPA-PSK')
pAP.wpa_pairwise = fixedValue(value='TKIP CCMP')
pAP.rsn_pairwise = fixedValue(value='CCMP')
pAP.usedhcp = ConfigYesNo(default=False)
pAP.address = ConfigIP(default=[0,
 0,
 0,
 0])
pAP.netmask = ConfigIP(default=[255,
 0,
 0,
 0])
pAP.gateway = ConfigIP(default=[0,
 0,
 0,
 0])
pAP.nameserver = ConfigIP(default=[0,
 0,
 0,
 0])

class APWiFimain(Screen, ConfigListScreen):
    if getDesktop(0).size().width() >= 1920:
        skinfile = '/usr/lib/enigma2/python/Plugins/SystemPlugins/WiFiAP/skin/fncap_1080.xml'
        skin = open(skinfile).read()
    else:
        skinfile = '/usr/lib/enigma2/python/Plugins/SystemPlugins/WiFiAP/skin/fncap_720.xml'
        skin = open(skinfile).read()

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self['shortcuts'] = ActionMap(['ShortcutActions', 'SetupActions'], {'ok': self.doConfigMsg,
         'cancel': self.keyCancel,
         'red': self.keyCancel,
         'green': self.doConfigMsg,
         'yellow': self.clientInfo}, -2)
        self.list = []
        ConfigListScreen.__init__(self, self.list, session=self.session)
        self['key_red'] = Label(_('Cancel'))
        self['key_green'] = Label(_('Apply'))
        self['key_yellow'] = Label(_(' '))
        self['key_blue'] = Label(_(' '))
        self['myText'] = Label()
        self['myText'].setText(self.readAPinfo())
        self['current_settings'] = StaticText(_('Current settings (interface : br0)'))
        self['IPAddress_text'] = StaticText(_('IP Address'))
        self['Netmask_text'] = StaticText(_('Netmask'))
        self['Gateway_text'] = StaticText(_('Gateway'))
        self['IPAddress'] = StaticText(_('N/A'))
        self['Netmask'] = StaticText(_('N/A'))
        self['Gateway'] = StaticText(_('N/A'))
        self.makeConfig()
        self.apModeChanged = False
        self.onClose.append(self.__onClose)
        self.onLayoutFinish.append(self.currentNetworkSettings)
        self.onLayoutFinish.append(self.checkConfigError)
        self.configErrorTimer = eTimer()
        self.configErrorTimer.callback.append(self.configErrorMsg)
        self.configStartMsg = None
        return

    def makeConfig(self):
        self.msg = ''
        if self.checkWirelessDevices():
            return
        self.loadInterfacesConfig()
        self.setupCurrentEncryption()
        self.createConfigEntry()
        self.createConfig()

    def checkConfigError(self):
        if self.msg:
            self.configErrorTimer.start(100, True)

    def configErrorMsg(self):
        self.session.openWithCallback(self.close, MessageBox, _(self.msg), MessageBox.TYPE_ERROR)

    def checkwlanDeviceList(self):
        if len(self.wlanDeviceList) == 0:
            self.checkwlanDeviceListTimer.start(100, True)

    def currentNetworkSettings(self):
        self['IPAddress'].setText(self.formatAddr(iNetwork.getAdapterAttribute('br0', 'ip')))
        self['Netmask'].setText(self.formatAddr(iNetwork.getAdapterAttribute('br0', 'netmask')))
        self['Gateway'].setText(self.formatAddr(iNetwork.getAdapterAttribute('br0', 'gateway')))

    def formatAddr(self, address = [0,
 0,
 0,
 0]):
        if address is None:
            return 'N/A'
        else:
            return '%d:%d:%d:%d' % (address[0],
             address[1],
             address[2],
             address[3])

    def checkWirelessDevices(self):
        global pAP
        global iface
        self.wlanDeviceList = []
        wlanIfaces = []
        for x in iNetwork.getInstalledAdapters():
            if x.startswith('eth') or x.startswith('br') or x.startswith('mon'):
                continue
            elif os_path.exists('/tmp/bcm/%s' % x):
                continue
            wlanIfaces.append(x)
            description = self.getAdapterDescription(x)
            if description == 'Unknown network adapter':
                self.wlanDeviceList.append((x, x))
            else:
                self.wlanDeviceList.append((x, description + ' (%s)' % x))

        if len(self.wlanDeviceList) == 0:
            self.msg = 'Can not find wireless lan devices that support AP mode.'
            return -1
        pAP.wirelessdevice = ConfigSelection(choices=self.wlanDeviceList)
        iface = pAP.wirelessdevice
        print '[Wireless Access Point]  WLANS ', str(self.wlanDeviceList)
        return 0

    def loadInterfacesConfig(self):
        try:
            fp = file('/etc/network/interfaces', 'r')
            datas = fp.readlines()
            fp.close()
        except:
            printDebugMsg('Read failed, /etc/network/interfaces.')
            return -1

        current_iface = ''
        try:
            for line in datas:
                split = line.strip().split(' ')
                if split[0] == 'iface':
                    current_iface = split[1]
                if current_iface == 'br0' or current_iface == 'eth0':
                    if len(split) == 4 and split[3] == 'dhcp':
                        pAP.usedhcp.value = True
                    if split[0] == 'address':
                        pAP.address.value = map(int, split[1].split('.'))
                    if split[0] == 'netmask':
                        pAP.netmask.value = map(int, split[1].split('.'))
                    if split[0] == 'gateway':
                        pAP.gateway.value = map(int, split[1].split('.'))
                    if split[0] == 'dns-nameservers':
                        pAP.nameserver.value = map(int, split[1].split('.'))

        except:
            printDebugMsg('Parsing failed, /etc/network/interfaces.')
            return -1

        return 0

    def formatIp(ip):
        if ip is None or len(ip) != 4:
            return '0.0.0.0'
        else:
            return '%d.%d.%d.%d' % (ip[0],
             ip[1],
             ip[2],
             ip[3])

    def setupCurrentEncryption(self):
        if len(pAP.wep_key0.value) > 10:
            pAP.wepType.value = '128'
        if pAP.wpa.value is not '0' and pAP.wpa_passphrase.value:
            pAP.encrypt.value = True
            pAP.method.value = pAP.wpa.value
        elif pAP.wep.value and pAP.wep_key0.value:
            pAP.encrypt.value = True
            pAP.method.value = '0'
        else:
            pAP.encrypt.value = False

    def createConfigEntry(self):
        self.useApEntry = getConfigListEntry(_('Activate AP'), pAP.useap)
        self.setupModeEntry = getConfigListEntry(_('Setup mode'), pAP.setupmode)
        self.wirelessDeviceEntry = getConfigListEntry(_('AP device'), pAP.wirelessdevice)
        if self.canAC(pAP.wirelessdevice.value):
            pAP.wirelessmode = ConfigSelection(default=' --ieee80211ac', choices=[(' --ieee80211ac', _('802.11ac mode (fastest)')), (' --ieee80211n', _('802.11n mode (fast)')), (' ', _('b+g mode (compatible with old stuff)'))])
        else:
            pAP.wirelessmode = ConfigSelection(default=' --ieee80211n', choices=[(' --ieee80211n', _('802.11n mode (fast)')), (' ', _('b+g mode (compatible with old stuff)'))])
        self.wirelessModeEntry = getConfigListEntry(_('AP mode (protocol)'), pAP.wirelessmode)
        self.showpluginEntry = getConfigListEntry(_('Show in plugins'), pAP.showplugin)
        self.bandEntry = getConfigListEntry(_('5 GHz band (faster) or 2.4 GHz (better penetration)'), pAP.band)
        self.channelEntry5 = getConfigListEntry(_('Channel for 5 GHz band (top range is country/adapter dependent'), pAP.channel5)
        self.channelEntry = getConfigListEntry(_('Channel for 2.4 GHz band'), pAP.channel)
        self.ssidEntry = getConfigListEntry(_('Access-point-name (SSID)'), pAP.ssid)
        self.beaconEntry = getConfigListEntry(_('Beacon (15~65535)'), pAP.beacon)
        self.rtsThresholdEntry = getConfigListEntry(_('RTS threshold (0~2347)'), pAP.rts_threshold)
        self.fragmThresholdEntry = getConfigListEntry(_('FRAGM threshold (256~2346)'), pAP.fragm_threshold)
        self.prambleEntry = getConfigListEntry(_('Preamble'), pAP.preamble)
        self.ignoreBroadcastSsid = getConfigListEntry(_('Ignore SSID broadcast'), pAP.ignore_broadcast_ssid)
        self.htcapsEntry = getConfigListEntry(_('2nd CH option (HT)'), pAP.htcaps)
        self.hiddenEntry = getConfigListEntry(_('Hide AP name'), pAP.hidden)
        self.countryEntry = getConfigListEntry(_('Region'), pAP.country)
        self.multipleEntry = getConfigListEntry(_('Allow additional APs (rarely supported by HW/SW)'), pAP.multiple)
        self.encryptEntry = getConfigListEntry(_('Encrypt'), pAP.encrypt)
        self.methodEntry = getConfigListEntry(_('Encryption type'), pAP.method)
        self.wepKeyTypeEntry = getConfigListEntry(_('KeyType'), pAP.wepType)
        self.wepKey0Entry = getConfigListEntry(_('WEP key (HEX)'), pAP.wep_key0)
        self.wpaKeyEntry = getConfigListEntry(_('Password (8~63 Characters)'), pAP.wpa_passphrase)
        self.groupRekeyEntry = getConfigListEntry(_('Group rekey interval'), pAP.wpagrouprekey)
        self.usedhcpEntry = getConfigListEntry(_('Use DHCP'), pAP.usedhcp)
        self.ipEntry = getConfigListEntry(_('IP address'), pAP.address)
        self.netmaskEntry = getConfigListEntry(_('NetMask'), pAP.netmask)
        self.gatewayEntry = getConfigListEntry(_('Gateway'), pAP.gateway)
        self.nameserverEntry = getConfigListEntry(_('Nameserver'), pAP.nameserver)

    def createConfig(self):
        pAP.address.value = iNetwork.getAdapterAttribute(pAP.bridge.value, 'ip') or [0,
         0,
         0,
         0]
        pAP.netmask.value = iNetwork.getAdapterAttribute(pAP.bridge.value, 'netmask') or [255,
         0,
         0,
         0]
        pAP.gateway.value = iNetwork.getAdapterAttribute(pAP.bridge.value, 'gateway') or [0,
         0,
         0,
         0]
        self.configList = []
        self.configList.append(self.useApEntry)
        self.configList.append(self.setupModeEntry)
        if pAP.useap.value is True:
            if pAP.setupmode.value is not 'preset':
                self.configList.append(self.wirelessDeviceEntry)
                self.configList.append(self.wirelessModeEntry)
                if self.can5ghz(pAP.wirelessdevice.value):
                    self.configList.append(self.bandEntry)
                    self.configList.append(self.channelEntry5)
                self.configList.append(self.channelEntry)
                self.configList.append(self.ssidEntry)
                if pAP.setupmode.value is 'advanced':
                    self.configList.append(self.htcapsEntry)
                    self.configList.append(self.hiddenEntry)
                self.configList.append(self.encryptEntry)
                if pAP.encrypt.value is True:
                    self.configList.append(self.methodEntry)
                    if pAP.method.value is '0':
                        self.configList.append(self.wepKeyTypeEntry)
                        self.configList.append(self.wepKey0Entry)
                    else:
                        self.configList.append(self.wpaKeyEntry)
                        if pAP.setupmode.value is 'advanced':
                            self.configList.append(self.groupRekeyEntry)
                if pAP.setupmode.value is 'advanced':
                    self.configList.append(self.countryEntry)
                    self.configList.append(self.multipleEntry)
                    self.configList.append(self.showpluginEntry)
        self['config'].list = self.configList
        self['config'].l.setList(self.configList)

    def keyLeft(self):
        ConfigListScreen.keyLeft(self)
        self.newConfig()

    def keyRight(self):
        ConfigListScreen.keyRight(self)
        self.newConfig()

    def newConfig(self):
        if self['config'].getCurrent() in [self.encryptEntry,
         self.methodEntry,
         self.useApEntry,
         self.usedhcpEntry,
         self.setupModeEntry]:
            self.createConfig()

    def doConfigMsg(self):
        msg = 'Apply the new settings?\n'
        isApMode = pAP.useap.value is True
        msg += '\n'
        self.session.openWithCallback(self.doConfig, MessageBox, _(msg))

    def doConfig(self, ret = False):
        if ret is not True:
            return
        if pAP.useap.value is True and pAP.encrypt.value is True:
            if not self.checkEncrypKey():
                return
        if not self.checkConfig():
            return
        self.startAP()

    def checkEncrypKey(self):
        if len(pAP.wpa_passphrase.value) not in range(8, 65):
            self.session.open(MessageBox, _('Invalid WPA Passphrase\n\n'), type=MessageBox.TYPE_ERROR, timeout=10)
        else:
            return True
        return False

    def checkConfig(self):
        if len(pAP.ssid.value) == 0 or len(pAP.ssid.value) > 32:
            self.session.open(MessageBox, _('Invalid SSID\n'), type=MessageBox.TYPE_ERROR, timeout=10)
            return False
        if pAP.wpagrouprekey.value < 0 or pAP.wpagrouprekey.value > 3600:
            self.session.open(MessageBox, _('Invalid wpagrouprekey\n'), type=MessageBox.TYPE_ERROR, timeout=10)
            return False
        return True

    def getAdapterDescription(self, iface):
        classdir = '/sys/class/net/' + iface + '/device/'
        driverdir = '/sys/class/net/' + iface + '/device/driver/'
        if os_path.exists(classdir):
            files = listdir(classdir)
            if 'driver' in files:
                if os_path.realpath(driverdir).endswith('rtw_usb_drv'):
                    return _('Realtek') + ' ' + _('WLAN adapter.')
                elif os_path.realpath(driverdir).endswith('ath_pci'):
                    return _('Atheros') + ' ' + _('WLAN adapter.')
                elif os_path.realpath(driverdir).endswith('zd1211b'):
                    return _('Zydas') + ' ' + _('WLAN adapter.')
                elif os_path.realpath(driverdir).endswith('rt73'):
                    return _('Ralink') + ' ' + _('WLAN adapter.')
                elif os_path.realpath(driverdir).endswith('rt73usb'):
                    return _('Ralink') + ' ' + _('WLAN adapter.')
                driver = str(os_path.basename(os_path.realpath(driverdir)))
                if driver == 'hif_pci':
                    return 'Qualcomm QCA6174 ac'
                else:
                    return str(os_path.basename(os_path.realpath(driverdir))) + ' ' + _('WLAN adapter')
            else:
                return _('Unknown network adapter')
        else:
            return _('Unknown network adapter')

    def __onClose(self):
        for x in self['config'].list:
            x[1].cancel()

        pAP.wpa.value = '0'
        pAP.wep.value = False

    def save(self):
        for x in self['config'].list:
            x[1].save()

    def keyCancel(self):
        self.close()

    def can5ghz(self, iface):
        if iface == 'wlan0':
            phy = 'phy0'
        elif iface == 'wlan1':
            phy = 'phy1'
        try:
            result = subprocess.check_output(['iw', phy, 'info'], stderr=subprocess.STDOUT)
        except:
            return False

        if '5180 MHz' in result:
            return True
        else:
            return False

    def canAC(self, iface):
        if iface == 'wlan0':
            phy = 'phy0'
        elif iface == 'wlan1':
            phy = 'phy1'
        try:
            result = subprocess.check_output(['iw', phy, 'info'], stderr=subprocess.STDOUT)
        except:
            return False

        if 'VHT' in result:
            return True
        else:
            return False

    def canN(self, iface):
        if iface == 'wlan0':
            phy = 'phy0'
        elif iface == 'wlan1':
            phy = 'phy1'
        try:
            result = subprocess.check_output(['iw', phy, 'info'], stderr=subprocess.STDOUT)
        except:
            return False

        if 'HT' in result:
            return True
        else:
            return False

    def writeAPinfo(self, apinfo):
        try:
            outF = open('/tmp/create_ap.common.conf/apinfo.txt', 'w')
            outF.write(apinfo)
            outF.close()
            return True
        except:
            return False

    def readAPinfo(self):
        global APINFO_ERR
        try:
            outF = open('/tmp/create_ap.common.conf/apinfo.txt', 'r')
            apinfo = outF.read()
            outF.close()
        except:
            apinfo = APINFO_ERR + '\n' + 'Prepare AP parameters - AP inactive '

        return apinfo

    def startAP(self):
        global APINFO_2
        global HOSTAPD_CONF
        global APINFO_1
        global APINFO_ERR
        if pAP.useap.value == False:
            for line in run_command('create_ap --stop ' + pAP.wirelessdevice.value):
                print line

            os_system('create_ap --stop wlan0')
            os_system('create_ap --stop wlan1')
            self.checkAP(False)
            return
        if self.checkAP(True) and not pAP.multiple.value:
            self.session.open(MessageBox, _('   AP is already active   '), MessageBox.TYPE_INFO, 5)
            return
        if pAP.setupmode.value == 'preset' and self.canAC(pAP.wirelessdevice.value):
            self.args = ' --daemon  --country AT --freq-band 5 --ieee80211ac --ht_capab [HT40+]  -m bridge wlan0 eth0 OpenFIX 12345678 '
        elif pAP.setupmode.value == 'preset' and self.can5ghz(pAP.wirelessdevice.value):
            self.args = ' --daemon --freq-band 5  --country AT --ieee80211n  -m bridge wlan0 eth0 OpenFIX 12345678 '
        elif pAP.setupmode.value == 'preset' and self.canN(pAP.wirelessdevice.value):
            self.args = ' --daemon --freq-band 2.4  --country AT  --ht_capab [SHORT-GI-20][SHORT-GI-40][HT40]  --ieee80211n -m bridge wlan0 eth0 OpenFIX 12345678 '
        elif pAP.setupmode.value == 'preset':
            self.args = ' --daemon --freq-band 2.4 --country AT   -m bridge wlan0 eth0 OpenFIX 12345678 '
        elif pAP.setupmode.value == 'simple' or pAP.setupmode.value == 'advanced':
            if pAP.band.value == ' --freq-band 5':
                chan = pAP.channel5.value
            else:
                chan = pAP.channel.value
            if pAP.encrypt.value == False:
                pkey = ' '
                encmethod = ' '
            else:
                pkey = pAP.wpa_passphrase.value
                encmethod = pAP.method.value
            if pAP.setupmode.value == 'simple':
                self.args = ' --daemon' + pAP.band.getValue() + pAP.wirelessmode.getValue() + ' -c ' + chan + ' --country AT -m bridge ' + pAP.wirelessdevice.value + ' eth0 ' + pAP.ssid.getValue() + ' ' + pkey
            else:
                self.args = ' --daemon' + pAP.band.getValue() + pAP.wirelessmode.getValue() + ' -c ' + chan + ' ' + pAP.country.value + ' ' + encmethod + pAP.hidden.getValue() + pAP.htcaps.getValue() + ' -m bridge ' + pAP.wirelessdevice.value + ' eth0 ' + pAP.ssid.getValue() + ' ' + pkey
        try:
            for line in run_command('create_ap ' + self.args):
                print line
                print '----------[APwifi   startAP()  ]   in run_command APINFO_ERR = ', APINFO_ERR
                if 'not support AP' in line:
                    APINFO_ERR = 'Your WiFi device does not support AP mode.'
                    pAP.useap.value = False
                    self.checkAP(False)
                    return
                if 'can not be a station' in line:
                    APINFO_ERR = 'Your WiFi device cannot be a station and AP.'
                    pAP.useap.value = False
                    self.checkAP(False)
                    return
                if 'is not a WiFi inter' in line:
                    APINFO_ERR = 'No suitable WiFi device.'
                    pAP.useap.value = False
                    self.checkAP(False)
                    return
                if 'Config dir' in line:
                    HOSTAPD_CONF = line.strip().split(':')[1]
                if 'Using interface' in line:
                    APINFO_1 = line
                if 'AP-ENABLED' in line:
                    break
                if 'IEEE 802.11 driver' in line:
                    APINFO_2 = line.strip().split(':')[2]

            self.writeAPinfo(APINFO_1 + APINFO_2)
            self.checkAP(False)
            return
        except:
            pAP.useap.value == False
            self.checkAP(False)
            return

    def checkAP(self, silent):
        if silent == True:
            if os_path.exists('/tmp/create_ap.common.conf'):
                return True
            else:
                return False
        sleep(2)
        if os_path.exists('/tmp/create_ap.common.conf'):
            self.session.open(MessageBox, _('   AP is:    active'), MessageBox.TYPE_INFO, 5)
            self.simplesetMyText()
            self.save()
            return True
        else:
            self.session.open(MessageBox, _('   AP is:    inactive'), MessageBox.TYPE_INFO, 5)
            self.simplesetMyText()
            return False

    def simplesetMyText(self):
        self['myText'].setText(self.readAPinfo())
        return
        print '----------[APwifi   simplesetMyText()  ]  AP, enabled = ', pAP.useap.value
        if pAP.useap.value == False:
            print '----------[APwifi   simplesetMyText()  ]  AP, enabled = ', pAP.useap.value
            self['myText'].setText('Prepare AP parameters')
            return
        print '----------[APwifi   simplesetMyText()  ]  AP, enabled = ', pAP.useap.value
        self['myText'].setText('AP active')
        try:
            self['myText'].setText(APINFO_2)
        except:
            if os_path.exists('/tmp/create_ap.common.conf'):
                self['myText'].setText('AP active')

    def clientInfo(self):
        try:
            statcmd = 'hostapd_cli -p ' + HOSTAPD_CONF + '/hostapd_ctrl/ '
            self.session.open(MessageBox, statcmd, MessageBox.TYPE_INFO)
            result = subprocess.check_output([statcmd, ' status'], stderr=subprocess.STDOUT)
            self.session.open(MessageBox, _(result), MessageBox.TYPE_INFO)
        except:
            pass


def main(session, **kwargs):
    session.open(APWiFimain)


def menuPanel(menuid, **kwargs):
    if menuid == 'fncmenu':
        return [('Setup WiFi AP',
          main,
          'setup_ap',
          4)]
    else:
        return []


def Plugins(**kwargs):
    lista = []
    if pAP.showplugin.value == True:
        lista.append(PluginDescriptor(name='Setup WiFi AP', description=_('Use a Wireless device as WiFi access point.'), where=PluginDescriptor.WHERE_PLUGINMENU, icon='ap.png', fnc=main))
    lista.append(PluginDescriptor(name='Setup WiFi AP', description=_('Use a Wireless device as WiFi access point.'), where=PluginDescriptor.WHERE_MENU, fnc=menuPanel))
    return lista
