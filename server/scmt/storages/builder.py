import consul


def build(options):
    if options['backend'] == 'consul':
        return consul.Consul(options['address'])
    else:
        raise IndexError("No such backend %s" % options['backend'])