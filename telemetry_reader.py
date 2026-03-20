import time
from datetime import datetime
import logging

logging.basicConfig(
    filename="syn_flood_detector.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S"
)

LEARNING_DURATION = 30
learning_count = 0

previous_passive = None
previous_fails = None
previous_syncookies = None
previous_overflows = None
previous_estab = None

syn_samples = []
fail_samples = []
cookie_samples = []
overflow_samples = []
estab_samples = []

baseline_syn = None
baseline_fail = None
baseline_cookie = None
baseline_overflow = None
baseline_estab = None

baseline_learned = False

def safe_delta(new, old):
	if new < old:
		return new
	return new - old

def timestamp():
	return datetime.now().strftime("[%H:%M:%S]")

print("[+] Starting Detector")
print("[+] Learning baseline for", LEARNING_DURATION, "seconds... \n")

try:
	while True:

		# Open and read file
		with open ("/proc/net/snmp") as f:
			snmp_data = f.read()

		with open ("/proc/net/netstat") as f:
			netstat_data = f.read()

		# split file into lines
		snmp_lines = snmp_data.split("\n")
		netstat_lines = netstat_data.split("\n")

		# Convert TCP field and value into List
		tcp_lines = []
		for line in snmp_lines:
			if line.startswith("Tcp:"):
				tcp_lines.append(line)

		tcp_ext = []
		for line in netstat_lines:
			if line.startswith("TcpExt:"):
				tcp_ext.append(line)
		# split Tcp lines individiually
		snmp_fields = tcp_lines[0].split()
		snmp_values = tcp_lines[1].split()

		netstat_fields = tcp_ext[0].split()
		netstat_values = tcp_ext[1].split()
		# pair corresponding values of both field: value

		snmp_metrics = dict(zip(snmp_fields, snmp_values))
		netstat_metrics = dict(zip(netstat_fields, netstat_values))

		# Converting into integer
		passive_opens = int(snmp_metrics["PassiveOpens"])
		attempt_fails = int(snmp_metrics["AttemptFails"])

		syncookies = int(netstat_metrics["SyncookiesSent"])
		listen_overflows = int(netstat_metrics["ListenOverflows"])

		curr_estab = int(snmp_metrics["CurrEstab"])

		# Rate Calculation
		if previous_passive is not None:

			syn_rate = safe_delta(passive_opens, previous_passive)
			fail_rate = safe_delta(attempt_fails, previous_fails)
			cookie_rate = safe_delta(syncookies, previous_syncookies)
			overflow_rate = safe_delta(listen_overflows, previous_overflows)
			estab_rate = safe_delta(curr_estab, previous_estab)
	
			#BASELINE LEARNING
			if not baseline_learned:
				syn_samples.append(syn_rate)
				fail_samples.append(fail_rate)
				cookie_samples.append(cookie_rate)
				overflow_samples.append(overflow_rate)
				estab_samples.append(estab_rate)
				learning_count+=1

				print(f"[LEARNING] SYN/sec: {syn_rate:<6} | Fail/sec: {fail_rate:<6} | Cookie/sec: {cookie_rate:<6} | Overflow/sec: {overflow_rate:<6}")

				if len(syn_samples) == LEARNING_DURATION:

					baseline_syn = sum(syn_samples)/len(syn_samples)
					baseline_fail = sum(fail_samples)/len(fail_samples)
					baseline_cookie = sum(cookie_samples)/len(cookie_samples)
					baseline_overflow = sum(overflow_samples)/len(overflow_samples)
					baseline_estab = sum(estab_samples)/len(estab_samples)

					print("\n[+] Baseline Learned")
					print("Baseline SYN/sec:", round(baseline_syn, 2))
					print("Baseline Fail/sec:", round(baseline_fail, 2))
					print("Baseline Cookie/sec:", round(baseline_cookie, 2))
					print("Baseline Overflow/sec:", round(baseline_overflow, 2))
					print("\n[+] Monitoring mode Started")

					baseline_learned = True

			# MONITORING MODE
			
			else:
				print(f"{timestamp()} SYN/sec: {syn_rate:<6} | Fail/sec: {fail_rate:<6} | Cookie/sec: {cookie_rate:<6} | Overflow/sec: {overflow_rate:<6}")

				if syn_rate > 0:
					completion_ratio = estab_rate / syn_rate
				else:
					completion_ratio = 1

				# SYN Rate severity
				if syn_rate > baseline_syn * 5:
					print(timestamp(), "[CRITICAL] Extreme SYN rate detected")
					logging.critical("Extreme SYN rate detected")
				elif syn_rate > baseline_syn * 3:
					print(timestamp(), "[ALERT] High SYN rate detected")
					logging.error("High SYN rate detected")
				elif syn_rate > baseline_syn * 2:
					print(timestamp(), "[WARNING] Elevated SYN rate detected")
					logging.warning("Elevated SYN rate detected")

				# Completion ratio
				if syn_rate > 0 and completion_ratio < 0.3:
					print(timestamp(), "[ALERT] Possible SYN flood (low completion ratio)")
					logging.error("Possible SYN flood (low completion ratio)")

				# SYN Cookies
				if cookie_rate > max(5, baseline_cookie * 5):
					print(timestamp(), "[ALERT] SYN Cookies rising — flood suspected")
					logging.error("SYN Cookies rising — flood suspected")
				elif cookie_rate > max(2, baseline_cookie * 2):
					print(timestamp(), "[WARNING] SYN Cookie usage elevated")
					logging.warning("SYN Cookie usage elevated")

				# Failed connections
				if fail_rate > max(10, baseline_fail * 5):
					print(timestamp(), "[ALERT] High failed connections detected")
					logging.error("High failed connections detected")
				elif fail_rate > max(5, baseline_fail * 2):
					print(timestamp(), "[WARNING] Elevated failed connections")
					logging.warning("Elevated failed connections")

				# Overflow — always critical
				if overflow_rate > 0:
					print(timestamp(), "[CRITICAL] Listen backlog overflow detected")
					logging.critical("Listen backlog overflow detected")

		previous_passive = passive_opens
		previous_fails = attempt_fails
		previous_syncookies = syncookies
		previous_overflows = listen_overflows
		previous_estab = curr_estab

		time.sleep(1)
except KeyboardInterrupt:
		print("\n[+] Detector stopped gracefully")
