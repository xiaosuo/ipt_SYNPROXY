<html>
<head>
<title>Summary</title>
<style type="text/css">
table {
	border: outset black;
	border-spacing: 0
}

th {
	border: inset gray;
	background-color: gray;
	width: 8em;
}

td {
	border: inset gray;
	text-align: right;
	width: 8em;
}
</style>
<script>
var timerId;
function refresh() {
	clearTimeout(timerId);
	now = new Date;
	window.location = "<?=$filename?>" + "?now=" + now.getTime();
}
timerId = setTimeout("refresh()", 3000);
</script>
</head>
<body>
<table>
	<tr><th>CPU</th><td><?=number_format($cpu, 2, ".", ",")?>%</td></tr>
	<tr><th>Memory</th><td><?=number_format($mem, 2, ".", ",")?>%</td></tr>
	<tr><th>Connection</th><td><?=$conn?></td></tr>
</table>
<br/>
<table>
	<tr>
		<th rowspan="2">NIC</th>
		<th colspan="2">RX</th>
		<th colspan="2">TX</th>
	</tr>
	<tr>
		<th>bps</th><th>pps</th><th>bps</th><th>pps</th>
	</tr>
<?	foreach ($nic as $name => $dev) { ?>
	<tr>
		<td><?=$name?></td>
		<td><?=number_format($dev["rx"]["bps"], 2, ".", ",")?></td>
		<td><?=number_format($dev["rx"]["pps"], 2, ".", ",")?></td>
		<td><?=number_format($dev["tx"]["bps"], 2, ".", ",")?></td>
		<td><?=number_format($dev["tx"]["pps"], 2, ".", ",")?></td>
	</tr>
<?	} ?>
</table>
</body>
</html>
