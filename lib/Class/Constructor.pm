

use strict;
use 5.005;
package Class::Constructor;
use Carp;
use File::Spec;

use vars qw($VERSION);

$VERSION = '1.1.0';

=head1 NAME

Class::Constructor - Simplify the creation of object constructors

=head1 SYNOPSIS

    package MyPackage;

    # Note if you don't have the CLASS package installed,
    # you can use the __PACKAGE__ keyword instead

    use CLASS;
    use base qw/ Class::Constructor Class::Accessor /;

    my @Accessors = qw(
        some_attribute
        another_attribute
        yet_another_attribute
    );

    CLASS->mk_accessors(@Accessors);
    CLASS->mk_constructor(
        Name           => 'new',
        Auto_Init      => \@Accessors,
    );

=head1 DESCRIPTION

Simplifies the creation of object constructors.

Instead of writing:

    sub new {
        my $proto = shift;
        my $class = ref $proto || $proto;
        my $self = {};
        bless $self, $class;

        my %args = @_;
        foreach my $attr ('first_attribute', 'second_attribute') {
            $self->$attr($args{$attr});
        }

        $self->_init();

        return $self;
    }

You can just write:

    CLASS->mk_constructor(
        Auto_Init      => [ 'first_attribute', 'second_attribute' ],
    );

There are other features as well:

=over 4

=item Automatically call other initialization methods.

Using the C<Init_Methods> method of C<mk_constructor>,
you can have your constructor method automatically call
one or more initialization methods.

=item Automatic Construction of objects of Subclasses

Your constructor can bless objects into one of
its subclasses.

For instance, the C<Fruit> class could bless objects
into the C<Fruit::Apple> or C<Fruit::Orange> classes
depending on a parameter passed to the constructor.

See L<Subclass_Param> for details.

=back

=head1 METHOD

=head2 mk_constructor

    CLASS->mk_constructor(
        Name           => 'new',
        Init_Methods   => [ '_init' ],
        Subclass_Param => 'Package_Type',
        Auto_Init      => [ 'first_attribute', 'second_attribute' ],
    );

The C<mk_constructor> method creates a constructor named C<Name> in
C<CLASS>'s namespace.

=over 4

=item Name

The name of the constructor method.  The default is C<new>.

=item Init_Methods

Cause the created constructor to call the listed methods
on all new objects that are created via the constructor.

    Foo->mk_constructor(
        Name           => 'new',
        Init_Methods   => '_init',
    );

    my $object = Foo->new; # This calls $object->_init();


    Foo->mk_constructor(
        Name           => 'new',
        Init_Methods   => [ '_init', '_startup' ],
    );

    my $object = Foo->new; # after construction, new()
                           # calls $object->_init(),
                           # then $object->_startup()


=item Subclass_Param

You can cause the constructor to make instances of a subclass,
based on the a special parameter passed to the constructor:

    # Fruit.pm:
    package Fruit;
    Fruit->mk_constructor(
        Name           => 'new',
        Subclass_Param => 'type',
    );

    sub has_core { 0 };

    # Fruit/Apple.pm:
    package Fruit::Apple;
    use base 'Fruit';

    sub has_core { 1 };

    # main program:
    package main;

    my $apple = Fruit->new(
        Type => 'Apple',
    );

    if ($apple->has_core) {
        print "apples have cores!\n";
    }

=item Dont_Load_Subclasses_Param

The name of the parameter that will be checked by the constructor
to determine whether or not subclasses specified by C<Subclass_Param>
will be loaded or not.  This is mainly useful if you are writing
test scripts and you want to load in your packages manually.

For instance:

    # Fruit.pm:
    package Fruit;
    Fruit->mk_constructor(
        Name                     => 'new',
        Subclass_Param           => 'type',
        Dont_Load_Subclass_Param => 'Dont_Load_Subclass',
    );

    # main program:
    package main;

    my $apple = Fruit->new(
        Type               => 'Apple',
        Dont_Load_Subclass => 1,
    );

Now when the C<$apple> object is created, the constructor makes no
attempt to require the C<Fruit::Apple> module.

=item Auto_Init

A list of attributes that should be automatically initialized via the
parameters to the constructor.

For each name/value pair passed to the constructor, the constructor
will call the method named C<name> with the parameter of C<value>.

For instance, if you make your constructor with:

    Fruit->mk_constructor(
        Auto_Init      => [ 'size', 'colour' ],
    );

And you call the constructor with:

    use Fruit;
    my $fruit = Fruit->new(
        Size   => 'big',
        Colour => 'red',
    );

Then, internally, the C<new> constructor will automatically call the
following methods:

    $fruit->size('big');
    $fruit->colour('red');

Note that the case of the arguments passed to the constructor
doesn't matter.  The following will also work:

    my $fruit = Fruit->new(
        SiZE   => 'big',
        colOUR => 'red',
    );

=back

=cut

sub mk_constructor {
    my $proto = shift;
    my $class = ref $proto || $proto;

    my %args = @_;

    my $constructor_name = $args{Name} || 'new';

    {
        no strict 'refs';
        return if defined &{"$class\:\:$constructor_name"};
    }

    my $subclass_param           = $args{Subclass_Param};
    my $dont_load_subclass_param = $args{Dont_Load_Subclass_Param};

    foreach my $arg (qw/Auto_Init Init_Method Init_Methods/) {
        next unless exists $args{$arg};
        $args{$arg} = [ $args{$arg} ] unless ref $args{$arg} eq 'ARRAY';
    }

    my @init_methods;
    push @init_methods, @{ $args{'Init_Method'} }  if exists $args{'Init_Method'};
    push @init_methods, @{ $args{'Init_Methods'} } if exists $args{'Init_Methods'};

    my @auto_init;
    push @auto_init, @{ $args{'Auto_Init'} } if exists $args{'Auto_Init'};
    my %auto_init = map { ($_) => 1 } @auto_init;

    my $constructor = sub {
        my $proto = shift;
        my $class = ref $proto || $proto;

        my %args = @_;
        my $self = {};

        my $load_subclasses = 1;

        if (defined $dont_load_subclass_param) {
            if (exists $args{$dont_load_subclass_param} and $args{$dont_load_subclass_param}) {
                delete $args{$dont_load_subclass_param};
                $load_subclasses = 0;
            }
        }

        if ($subclass_param and exists $args{$subclass_param}) {
            my $subclass = $args{$subclass_param};

            delete $args{$subclass_param} unless $auto_init{ $subclass_param} or @init_methods;

            $class .= "::$subclass";

            if ($load_subclasses) {
                my @class_fn = split /::/, $class;
                my $class_fn = File::Spec->join(split /::/, $class);
                $class_fn   .= '.pm';

                require $class_fn;
            }
        }

        bless $self, $class;

        foreach my $attr (keys %args) {
            my $method =  $attr;
            if ($auto_init{$method}) {
                $self->$method($args{$attr});
            }
            else {
                unless (@init_methods) {
                    croak "Can't autoinitialize method $method from $attr\n";
                }
            }
        }

        foreach my $init_method (@init_methods) {
            $self->$init_method(@_);
        }

        return $self;
    };

    {
        no strict 'refs';
        *{"$class\:\:$constructor_name"} = $constructor;
    }
    return 1;
}


1;

=head1 AUTHOR

Michael Graham E<lt>mag-perl@occamstoothbrush.comE<gt>

Copyright (C) 2001 Michael Graham.  All rights reserved.
This program is free software.  You can use, modify,
and distribute it under the same terms as Perl itself.

The latest version of this module can be found on http://www.occamstoothbrush.com/perl/

12/16/03 modified by Dana Hudes E<lt>dhudes@hudes.orgE<gt> to remove code
that changed case of accessors.

=head1 SEE ALSO

=over 4

=item Class::Accessor

=item CLASS

=back

=cut
