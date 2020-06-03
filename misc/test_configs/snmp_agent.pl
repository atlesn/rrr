use SNMP::Agent;
 
my $root_oid = 'netSnmpPlaypen.7375.1';
 
my @wasting_time = qw/Sittin' on the dock of the bay/;
 
sub stats_handler {
  my $oid = shift;     # a NetSNMP::OID object
 
  return "root oid" if($oid =~ /$root_oid$/);
 
  my $idx = ($oid->to_array())[$oid->length - 1];
  return $wasting_time[$idx - 1];
}
 
sub next_oid_handler {
  my $oid = shift;
 
  if($oid eq $root_oid) {
    return join('.', ($root_oid, '.1'));
  }
 
  if($oid =~ /$root_oid\.(\d+)$/) {
    my $idx = $1;
    if ($idx <= $#wasting_time)
    {
      my $next_oid = join('.', ($root_oid, $idx + 1));
      return $next_oid;
    }
  }
 
  return;     # no next OID
}
 
my %handlers = (
  $root_oid => { handler => \&stats_handler },
);
 
my $agent = new SNMP::Agent('my_agent', '', \%handlers);
$agent->register_get_next_oid(\&next_oid_handler);
$agent->run();
