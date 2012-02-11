#!/usr/bin/env php
<?php

class CpuUsage {
	var $m_total;
	var $m_idle;
	var $m_result;

	function __get_data(&$total, &$idle) {
		$lines = file("/proc/stat");
		$trunks = preg_split("/\s+/", trim($lines[0]));
		array_shift($trunks);
		$total = 0;
		foreach ($trunks as $i => $usage) {
			$total += $usage;
			if ($i == 3)
				$idle = $usage;
		}
	}

	function CpuUsage() {
		$this->__get_data($this->m_total, $this->m_idle);
		$this->m_result = 0;
	}

	function get() {
		$this->__get_data($total, $idle);
		if ($total == $this->m_total)
			return $this->m_result;
		$this->m_result = 100 - ($idle - $this->m_idle) * 100 /
				($total - $this->m_total);
		$this->m_result = round($this->m_result, 2);
		$this->m_total = $total;
		$this->m_idle = $idle;

		return $this->m_result;
	}
}

class MemoryUsage {
	function get() {
		$lines = file("/proc/meminfo");
		$mm = array();
		foreach ($lines as $line) {
			$trunks = preg_split("/[\s:]+/", trim($line));
			$mm[$trunks[0]] = $trunks[1];
		}

		return round(($mm["MemTotal"] - $mm["MemFree"] -
			      $mm["Buffers"] - $mm["Cached"]) * 100
			     / $mm["MemTotal"], 2);
	}
}

class Connection {
	function get() {
		return intval(trim(file_get_contents("/proc/sys/net/ipv4/netfilter/ip_conntrack_count")));
	}
}

class Nic {
	var $m_dev;
	var $m_result;
	var $m_last;

	function Nic() {
		$this->m_last = time();
		$this->m_result = array();
		$this->__sample($this->m_dev);
	}

	function get($nic_name) {
		if (!isset($this->m_dev[$nic_name]))
			return 0;

		$delta = time() - $this->m_last;
		if ($delta == 0)
			return $this->m_result[$nic_name];
		$this->m_last += $delta;
		$this->__sample($devs);

		foreach ($devs as $name => $dev) {
			$this->m_result[$name]["rx"]["pps"] = round(($dev["rx"]["packets"] - $this->m_dev[$name]["rx"]["packets"]) / $delta, 2);
			$this->m_result[$name]["rx"]["bps"] = round(($dev["rx"]["bytes"] - $this->m_dev[$name]["rx"]["bytes"]) * 8/ $delta, 2);
			$this->m_result[$name]["tx"]["pps"] = round(($dev["tx"]["packets"] - $this->m_dev[$name]["tx"]["packets"]) / $delta, 2);
			$this->m_result[$name]["tx"]["bps"] = round(($dev["tx"]["bytes"] - $this->m_dev[$name]["tx"]["bytes"]) * 8/ $delta, 2);
		}
		$this->m_dev = $devs;

		return $this->m_result[$nic_name];
	}

	function getAll() {
		$result = array();

		foreach ($this->m_dev as $name => $dev) {
			$result[$name] = $this->get($name);
		}

		return $result;
	}

	function __sample(&$dev) {
		$dev = array();
		$lines = file("/proc/net/dev");
		array_shift($lines);
		array_shift($lines);
		foreach ($lines as $line) {
			$trunks = preg_split("/[\s:]+/", $line);
			while ($trunks[0] == "")
				array_shift($trunks);
			if ($trunks[0] == "lo")
				continue;
			$dev[$trunks[0]]["rx"]["bytes"] = $trunks[1];
			$dev[$trunks[0]]["rx"]["packets"] = $trunks[2];
			$dev[$trunks[0]]["tx"]["bytes"] = $trunks[9];
			$dev[$trunks[0]]["tx"]["packets"] = $trunks[10];
		}
	}
}

class Summary {
	var $cpu, $mem, $nic, $conn;

	function Summary() {
		$this->cpu = new CpuUsage();
		$this->mem = new MemoryUsage();
		$this->nic = new Nic();
		$this->conn = new Connection();
	}

	function output($filename) {
		$cpu = $this->cpu->get();
		$mem = $this->mem->get();
		$nic = $this->nic->getAll();
		$conn = $this->conn->get();
		ob_start();
		include($filename . ".tpl");
		$contents = ob_get_contents();
		ob_end_clean();
		$fp = fopen($filename . ".tmp", "w");
		fwrite($fp, $contents);
		fclose($fp);
		rename($filename . ".tmp", $filename);
	}
}

$sum = new Summary();
while (1) {
	sleep(3);
	$sum->output("summary.html");
}

?>
