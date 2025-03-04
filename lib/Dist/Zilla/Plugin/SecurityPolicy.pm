package Dist::Zilla::Plugin::SecurityPolicy;

use strict;
use warnings;
no autovivification;

use Moose;
with qw/Dist::Zilla::Role::FileGatherer Dist::Zilla::Role::PrereqSource Dist::Zilla::Role::FilePruner/;

use MooseX::Types::Moose qw/Str Bool HashRef/;
use MooseX::Types::Perl qw/StrictVersionStr/;

use Carp 'croak';
use Module::Runtime 'require_module';

has policy_class => (
	is       => 'ro',
	isa      => Str,
	required => 1,
);

has policy_args => (
	isa      => HashRef,
	traits   => ['Hash'],
	default  => sub { {} },
	handles  => {
		policy_args => 'elements',
	}
);

has policy_version => (
	is       => 'ro',
	isa      => StrictVersionStr,
	default  => '0',
);

has filename => (
	is       => 'ro',
	isa      => Str,
	default  => 'SECURITY.md',
);

has auto_url => (
	is       => 'ro',
	isa      => Bool,
	default  => !!0,
);

around plugin_from_config => sub {
	my ($orig, $class, $name, $args, $section) = @_;

	my (%module_args, %policy_args);
	for my $key (keys %{ $args }) {
		if ($key =~ s/^-//) {
			$module_args{$key} = $args->{"-$key"};
		} else {
			$module_args{policy_args}{$key} = $args->{$key};
		}
	}

	if (!$module_args{policy_class}) {
		my $policy_name = $module_args{policy} or croak "No security policy was given";
		$module_args{policy_class} = "Software::Security::Policy::$policy_name";
	}

	return $class->$orig($name, \%module_args, $section);
};

sub gather_files {
	my ($self) = @_;

	my $zilla = $self->zilla;
	my %policy_args = (
		maintainer => join(', ', @{ $zilla->authors }),
		program    => $zilla->name,
		$self->policy_args,
	);

	if ($self->auto_url) {
		if (my $base = $zilla->distmeta->{resources}{repository}{web}) {
			if ($base =~ m{https://github.com/([\w-]+/[\w-]+)}) {
				$policy_args{url} = "$base/blob/HEAD/" . $self->filename;
			}
			# also need gitlab and others here
		}
	}

	require_module($self->policy_class);
	my $policy = $self->policy_class->new(\%policy_args);

	require Dist::Zilla::File::InMemory;
	$self->add_file(Dist::Zilla::File::InMemory->new(
		name     => $self->filename,
		content  => $policy->fulltext,
	));

	return;
}

sub register_prereqs {
	my $self = shift;
	$self->zilla->register_prereqs({ phase => 'develop' }, $self->policy_class => $self->policy_version);
	return;
}

sub prune_files {
	my $self = shift;

	my @files = @{ $self->zilla->files };
	my $filename = $self->filename;
	for my $file (@files) {
		$self->zilla->prune_file($file) if $file->name eq $filename and $file->added_by !~ __PACKAGE__;
	}
}

__PACKAGE__->meta->make_immutable;

no Moose;

1;

# ABSTRACT: Add a SECURITY.md to your dzil distribution

=head1 SYNOPSIS

 [SecurityPolicy]
 -policy = Individual
 -auto_url = 1
 timeframe = 2 weeks

=head1 DESCRIPTION

This plugin adds a SECURITY.md file as generated using L<Software::Security::Policy|Software::Security::Policy>. Any options to this plugin that are prefixed by C<-> are kept for this module, any others will be passed to the constructor of the security policy.

=attr policy_class

E.g. C<policy_class = Software::Security::Policy::Individual>

This sets the used policy class.

=attr policy

E.g. C<policy = Individual>

This is a short hand for setting the policy, allowing you to skip prepending C<Software::Security::Policy::>

=attr policy_version

The minimum version of the policy class, defaults to C<0>.

=attr filename

This allows you to override the name of the security file. It default to C<SECURITY.md> and you should probably not change it.

=attr auto_url

If set to C<1>, this adds a url argument to the policy pointing to the expected location of the security file as derived from the git remote.
