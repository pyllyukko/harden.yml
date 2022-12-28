#!/usr/bin/env perl
#Copied from https://github.com/mwlucas/books/blob/master/sudo_mastery/backup-alias.pl
#Takes a digest list of command aliases and builds an alias
#named SHELLS containing select commands
die unless (open(DIGESTS, $ARGV[0]));

print "Cmnd_Alias SHELLS = ";
while (<DIGESTS>) {
  chomp;
  next unless /^Cmnd_Alias/;
  my ($discard, $CmndAlias, $equal, $hash, $command) = split;
  next unless ($command =~ m'^/bin/sh$|^/bin/bash$|^/bin/dash$|^/bin/zsh$|^/bin/csh$|^/bin/tcsh$');
  print "$CmndAlias, ";
}

#An alias cannot end with a comma, so list a non-runnable non-existent
#thing at the end
print "/nonexistent\n\n";

#support both wheel and sudo groups for cross-platform
print "%wheel ALL=(root) TIMEOUT=15m PASSWD:EXEC: SHELLS\n";
print "%sudo ALL=(root) TIMEOUT=15m PASSWD:EXEC: SHELLS\n";
