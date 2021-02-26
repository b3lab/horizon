#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2017 TUBITAK B3LAB
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

UNIV_CHOICES = (
    ("tubitak.gov.tr", "TÜBITAK"),    
    ("ibu.edu.tr", "ABANT İZZET BAYSAL ÜNİVERSİTESİ"),
    ("agu.edu.tr", "ABDULLAH GÜL ÜNİVERSİTESİ"),
    ("acibadem.edu.tr", "ACIBADEM ÜNİVERSİTESİ"),
    ("adanabtu.edu.tr", "ADANA BİLİM VE TEKNOLOJİ ÜNİVERSİTESİ"),
    ("adiyaman.edu.tr", "ADIYAMAN ÜNİVERSİTESİ"),
    ("adu.edu.tr", "ADNAN MENDERES ÜNİVERSİTESİ"),
    ("aku.edu.tr", "AFYON KOCATEPE ÜNİVERSİTESİ"),
    ("agri.edu.tr", "AĞRI İBRAHİM ÇEÇEN ÜNİVERSİTESİ"),
    ("ahievran.edu.tr", "AHİ EVRAN ÜNİVERSİTESİ"),
    ("akdeniz.edu.tr", "AKDENİZ ÜNİVERSİTESİ"),
    ("aksaray.edu.tr", "AKSARAY ÜNİVERSİTESİ"),
    ("alanya.edu.tr", "ALANYA ALAADDİN KEYKUBAT ÜNİVERSİTESİ"),
    ("ahep.edu.tr", "ALANYA HAMDULLAH EMİN PAŞA ÜNİVERSİTESİ"),
    ("amasya.edu.tr", "AMASYA ÜNİVERSİTESİ"),
    ("anadolu.edu.tr", "ANADOLU ÜNİVERSİTESİ"),
    ("asbu.edu.tr", "ANKARA SOSYAL BİLİMLER ÜNİVERSİTESİ"),
    ("ankara.edu.tr", "ANKARA ÜNİVERSİTESİ"),
    ("akev.edu.tr", "ANTALYA AKEV ÜNİVERSİTESİ"),
    ("ardahan.edu.tr", "ARDAHAN ÜNİVERSİTESİ"),
    ("artvin.edu.tr", "ARTVİN ÇORUH ÜNİVERSİTESİ"),
    ("adiguzel.edu.tr", "ATAŞEHİR ADIGÜZEL MESLEK YÜKSEKOKULU"),
    ("atauni.edu.tr", "ATATÜRK ÜNİVERSİTESİ"),
    ("atilim.edu.tr", "ATILIM ÜNİVERSİTESİ"),
    ("avrasya.edu.tr", "AVRASYA ÜNİVERSİTESİ"),
    ("avrupa.edu.tr", "AVRUPA MESLEK YÜKSEKOKULU"),
    ("bau.edu.tr", "BAHÇEŞEHİR ÜNİVERSİTESİ"),
    ("balikesir.edu.tr", "BALIKESİR ÜNİVERSİTESİ"),
    ("bandirma.edu.tr", "BANDIRMA ONYEDİ EYLÜL ÜNİVERSİTESİ"),
    ("bartin.edu.tr", "BARTIN ÜNİVERSİTESİ"),
    ("baskent.edu.tr", "BAŞKENT ÜNİVERSİTESİ"),
    ("batman.edu.tr", "BATMAN ÜNİVERSİTESİ"),
    ("bayburt.edu.tr", "BAYBURT ÜNİVERSİTESİ"),
    ("beykent.edu.tr", "BEYKENT ÜNİVERSİTESİ"),
    ("beykoz.edu.tr", "BEYKOZ LOJİSTİK MESLEK YÜKSEKOKULU"),
    ("bezmialem.edu.tr", "BEZM-İ ÂLEM VAKIF ÜNİVERSİTESİ"),
    ("bilecik.edu.tr", "BİLECİK ŞEYH EDEBALİ ÜNİVERSİTESİ"),
    ("bingol.edu.tr", "BİNGÖL ÜNİVERSİTESİ"),
    ("biruni.edu.tr", "BİRUNİ ÜNİVERSİTESİ"),
    ("beu.edu.tr", "BİTLİS EREN ÜNİVERSİTESİ"),
    ("boun.edu.tr", "BOĞAZİÇİ ÜNİVERSİTESİ"),
    ("bozok.edu.tr", "BOZOK ÜNİVERSİTESİ"),
    ("btu.edu.tr", "BURSA TEKNİK ÜNİVERSİTESİ"),
    ("beun.edu.tr", "BÜLENT ECEVİT ÜNİVERSİTESİ"),
    ("cbu.edu.tr", "CELÂL BAYAR ÜNİVERSİTESİ"),
    ("cumhuriyet.edu.tr", "CUMHURİYET ÜNİVERSİTESİ"),
    ("cag.edu.tr", "ÇAĞ ÜNİVERSİTESİ"),
    ("comu.edu.tr", "ÇANAKKALE ONSEKİZ MART ÜNİVERSİTESİ"),
    ("cankaya.edu.tr", "ÇANKAYA ÜNİVERSİTESİ"),
    ("cu.edu.tr", "ÇUKUROVA ÜNİVERSİTESİ"),
    ("dicle.edu.tr", "DİCLE ÜNİVERSİTESİ"),
    ("dogus.edu.tr", "DOĞUŞ ÜNİVERSİTESİ"),
    ("deu.edu.tr", "DOKUZ EYLÜL ÜNİVERSİTESİ"),
    ("dpu.edu.tr", "DUMLUPINAR ÜNİVERSİTESİ"),
    ("duzce.edu.tr", "DÜZCE ÜNİVERSİTESİ"),
    ("mail.ege.edu.tr", "EGE ÜNİVERSİTESİ"),
    ("erciyes.edu.tr", "ERCİYES ÜNİVERSİTESİ"),
    ("erzincan.edu.tr", "ERZİNCAN ÜNİVERSİTESİ"),
    ("erzurum.edu.tr", "ERZURUM TEKNİK ÜNİVERSİTESİ"),
    ("ogu.edu.tr", "ESKİŞEHİR OSMANGAZİ ÜNİVERSİTESİ"),
    ("faruksarac.edu.tr", "FARUK SARAÇ TASARIM MESLEK YÜKSEKOKULU"),
    ("fsm.edu.tr", "FATİH SULTAN MEHMET VAKIF ÜNİVERSİTESİ"),
    ("firat.edu.tr", "FIRAT ÜNİVERSİTESİ"),
    ("gsu.edu.tr", "GALATASARAY ÜNİVERSİTESİ"),
    ("gazi.edu.tr", "GAZİ ÜNİVERSİTESİ"),
    ("gantep.edu.tr", "GAZİANTEP ÜNİVERSİTESİ"),
    ("gop.edu.tr", "GAZİOSMANPAŞA ÜNİVERSİTESİ"),
    ("gtu.edu.tr", "GEBZE TEKNİK ÜNİVERSİTESİ"),
    ("gedik.edu.tr", "GEDİK ÜNİVERSİTESİ"),
    ("giresun.edu.tr", "GİRESUN ÜNİVERSİTESİ"),
    ("gumushane.edu.tr", "GÜMÜŞHANE ÜNİVERSİTESİ"),
    ("hacettepe.edu.tr", "HACETTEPE ÜNİVERSİTESİ"),
    ("hakkari.edu.tr", "HAKKARİ ÜNİVERSİTESİ"),
    ("halic.edu.tr", "HALİÇ ÜNİVERSİTESİ"),
    ("harran.edu.tr", "HARRAN ÜNİVERSİTESİ"),
    ("hku.edu.tr", "HASAN KALYONCU ÜNİVERSİTESİ"),
    ("hitit.edu.tr", "HİTİT ÜNİVERSİTESİ"),
    ("igdir.edu.tr", "IĞDIR ÜNİVERSİTESİ"),
    ("isikun.edu.tr", "IŞIK ÜNİVERSİTESİ"),
    ("bilkent.edu.tr", "İHSAN DOĞRAMACI BİLKENT ÜNİVERSİTESİ"),
    ("inonu.edu.tr", "İNÖNÜ ÜNİVERSİTESİ"),
    ("iste.edu.tr", "İSKENDERUN TEKNİK ÜNİVERSİTESİ"),
    ("arel.edu.tr", "İSTANBUL AREL ÜNİVERSİTESİ"),
    ("aydin.edu.tr", "İSTANBUL AYDIN ÜNİVERSİTESİ"),
    ("bilgi.edu.tr", "İSTANBUL BİLGİ ÜNİVERSİTESİ"),
    ("istanbulbilim.edu.tr", "İSTANBUL BİLİM ÜNİVERSİTESİ"),
    ("esenyurt.edu.tr", "İSTANBUL ESENYURT ÜNİVERSİTESİ"),
    ("gelisim.edu.tr", "İSTANBUL GELİŞİM ÜNİVERSİTESİ"),
    ("kavram.edu.tr", "İSTANBUL KAVRAM MESLEK YÜKSEKOKULU"),
    ("kemerburgaz.edu.tr", "İSTANBUL KEMERBURGAZ ÜNİVERSİTESİ"),
    ("iku.edu.tr", "İSTANBUL KÜLTÜR ÜNİVERSİTESİ"),
    ("medeniyet.edu.tr", "İSTANBUL MEDENİYET ÜNİVERSİTESİ"),
    ("medipol.edu.tr", "İSTANBUL MEDİPOL ÜNİVERSİTESİ"),
    ("rumeli.edu.tr", "İSTANBUL RUMELİ ÜNİVERSİTESİ"),
    ("izu.edu.tr", "İSTANBUL SABAHATTİN ZAİM ÜNİVERSİTESİ"),
    ("sehir.edu.tr", "İSTANBUL ŞEHİR ÜNİVERSİTESİ"),
    ("sisli.edu.tr", "İSTANBUL ŞİŞLİ MESLEK YÜKSEKOKULU"),
    ("itu.edu.tr", "İSTANBUL TEKNİK ÜNİVERSİTESİ"),
    ("ticaret.edu.tr", "İSTANBUL TİCARET ÜNİVERSİTESİ"),
    ("istanbul.edu.tr", "İSTANBUL ÜNİVERSİTESİ"),
    ("29mayis.edu.tr", "İSTANBUL 29 MAYIS ÜNİVERSİTESİ"),
    ("istinye.edu.tr", "İSTİNYE ÜNİVERSİTESİ"),
    ("ieu.edu.tr", "İZMİR EKONOMİ ÜNİVERSİTESİ"),
    ("ikc.edu.tr", "İZMİR KATİP ÇELEBİ ÜNİVERSİTESİ"),
    ("iyte.edu.tr", "İZMİR YÜKSEK TEKNOLOJİ ENSTİTÜSÜ"),
    ("khas.edu.tr", "KADİR HAS ÜNİVERSİTESİ"),
    ("kafkas.edu.tr", "KAFKAS ÜNİVERSİTESİ"),
    ("ksu.edu.tr", "KAHRAMANMARAŞ SÜTÇÜ İMAM ÜNİVERSİTESİ"),
    ("kapadokya.edu.tr", "KAPADOKYA MESLEK YÜKSEKOKULU"),
    ("karabuk.edu.tr", "KARABÜK ÜNİVERSİTESİ"),
    ("ktu.edu.tr", "KARADENİZ TEKNİK ÜNİVERSİTESİ"),
    ("kmu.edu.tr", "KARAMANOĞLU MEHMETBEY ÜNİVERSİTESİ"),
    ("kastamonu.edu.tr", "KASTAMONU ÜNİVERSİTESİ"),
    ("kku.edu.tr", "KIRIKKALE ÜNİVERSİTESİ"),
    ("klu.edu.tr", "KIRKLARELİ ÜNİVERSİTESİ"),
    ("kilis.edu.tr", "KİLİS 7 ARALIK ÜNİVERSİTESİ"),
    ("kocaeli.edu.tr", "KOCAELİ ÜNİVERSİTESİ"),
    ("ku.edu.tr", "KOÇ ÜNİVERSİTESİ"),
    ("gidatarim.edu.tr", "KONYA GIDA VE TARIM ÜNİVERSİTESİ"),
    ("karatay.edu.tr", "KTO KARATAY ÜNİVERSİTESİ"),
    ("maltepe.edu.tr", "MALTEPE ÜNİVERSİTESİ"),
    ("artuklu.edu.tr", "MARDİN ARTUKLU ÜNİVERSİTESİ"),
    ("marmara.edu.tr", "MARMARA ÜNİVERSİTESİ"),
    ("mef.edu.tr", "MEF ÜNİVERSİTESİ"),
    ("mehmetakif.edu.tr", "MEHMET AKİF ERSOY ÜNİVERSİTESİ"),
    ("mersin.edu.tr", "MERSİN ÜNİVERSİTESİ"),
    ("msgsu.edu.tr", "MİMAR SİNAN GÜZEL SANATLAR ÜNİVERSİTESİ"),
    ("mu.edu.tr", "MUĞLA SITKI KOÇMAN ÜNİVERSİTESİ"),
    ("mku.edu.tr", "MUSTAFA KEMAL ÜNİVERSİTESİ"),
    ("alparslan.edu.tr", "MUŞ ALPARSLAN ÜNİVERSİTESİ"),
    ("nku.edu.tr", "NAMIK KEMAL ÜNİVERSİTESİ"),
    ("konya.edu.tr", "NECMETTİN ERBAKAN ÜNİVERSİTESİ"),
    ("nevsehir.edu.tr", "NEVŞEHİR HACI BEKTAŞ VELİ ÜNİVERSİTESİ"),
    ("nigde.edu.tr", "NİĞDE ÜNİVERSİTESİ"),
    ("nisantasi.edu.tr", "NİŞANTAŞI ÜNİVERSİTESİ"),
    ("nny.edu.tr", "NUH NACİ YAZGAN ÜNİVERSİTESİ"),
    ("okan.edu.tr", "OKAN ÜNİVERSİTESİ"),
    ("omu.edu.tr", "ONDOKUZ MAYIS ÜNİVERSİTESİ"),
    ("odu.edu.tr", "ORDU ÜNİVERSİTESİ"),
    ("metu.edu.tr", "ORTA DOĞU TEKNİK ÜNİVERSİTESİ"),
    ("osmaniye.edu.tr", "OSMANİYE KORKUT ATA ÜNİVERSİTESİ"),
    ("ozu.edu.tr,ozyegin.edu.tr", "ÖZYEĞİN ÜNİVERSİTESİ"),
    ("pau.edu.tr", "PAMUKKALE ÜNİVERSİTESİ"),
    ("pirireis.edu.tr", "PİRİ REİS ÜNİVERSİTESİ"),
    ("plato.edu.tr", "PLATO MESLEK YÜKSEKOKULU"),
    ("erdogan.edu.tr", "RECEP TAYYİP ERDOĞAN ÜNİVERSİTESİ"),
    ("sabanciuniv.edu", "SABANCI ÜNİVERSİTESİ"),
    ("sbu.edu.tr", "SAĞLIK BİLİMLERİ ÜNİVERSİTESİ"),
    ("sakarya.edu.tr", "SAKARYA ÜNİVERSİTESİ"),
    ("sanko.edu.tr", "SANKO ÜNİVERSİTESİ"),
    ("selcuk.edu.tr", "SELÇUK ÜNİVERSİTESİ"),
    ("siirt.edu.tr", "SİİRT ÜNİVERSİTESİ"),
    ("sinop.edu.tr", "SİNOP ÜNİVERSİTESİ"),
    ("sdu.edu.tr", "SÜLEYMAN DEMİREL ÜNİVERSİTESİ"),
    ("sirnak.edu.tr", "ŞIRNAK ÜNİVERSİTESİ"),
    ("tedu.edu.tr", "TED ÜNİVERSİTESİ"),
    ("etu.edu.tr", "TOBB EKONOMİ VE TEKNOLOJİ ÜNİVERSİTESİ"),
    ("toros.edu.tr", "TOROS ÜNİVERSİTESİ"),
    ("trakya.edu.tr", "TRAKYA ÜNİVERSİTESİ"),
    ("tunceli.edu.tr", "TUNCELİ ÜNİVERSİTESİ"),
    ("thk.edu.tr", "TÜRK HAVA KURUMU ÜNİVERSİTESİ"),
    ("tau.edu.tr", "TÜRK-ALMAN ÜNİVERSİTESİ"),
    ("ufuk.edu.tr", "UFUK ÜNİVERSİTESİ"),
    ("uludag.edu.tr", "ULUDAĞ ÜNİVERSİTESİ"),
    ("antalya.edu.tr", "ULUSLARARASI ANTALYA ÜNİVERSİTESİ"),
    ("usak.edu.tr", "UŞAK ÜNİVERSİTESİ"),
    ("uskudar.edu.tr", "ÜSKÜDAR ÜNİVERSİTESİ"),
    ("yalova.edu.tr", "YALOVA ÜNİVERSİTESİ"),
    ("yasar.edu.tr", "YAŞAR ÜNİVERSİTESİ"),
    ("yeditepe.edu.tr", "YEDİTEPE ÜNİVERSİTESİ"),
    ("yeniyuzyil.edu.tr", "YENİ YÜZYIL ÜNİVERSİTESİ"),
    ("ybu.edu.tr", "YILDIRIM BEYAZIT ÜNİVERSİTESİ"),
    ("yildiz.edu.tr", "YILDIZ TEKNİK ÜNİVERSİTESİ"),
    ("yiu.edu.tr", "YÜKSEK İHTİSAS ÜNİVERSİTESİ"),
    ("yyu.edu.tr", "YÜZÜNCÜ YIL ÜNİVERSİTESİ")
)
