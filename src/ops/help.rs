use std::env::Args;

use crate::error;

pub fn run(mut args: Args) -> error::Result<()> {
    let mut op: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        if op.is_none() {
            op = Some(arg);
        } else {
            return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("operation was already specified"))
        }
    }

    if let Some(op) = op {
        match op.as_str() {
            "codes" => {
                println!("codes [options]

prints generated codes to the terminal

options
    -w | --watch  prints codes to the terminal every second
    -f | --file   specifies which file to open and view codes for
    -n | --name   attempts to find the desired records in a given file

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified");
            },
            "new" => {
                println!("new [options]

generates a new encrypted totp file. the user will be prompted to enter a
secret in order to encrypt the file.

options
    -d | --directory  the specified directory to create the new file
    -n | --name       the name of the file REQUIRED");
            },
            "add" => {
                println!("add [options]

adds a new record to a totp file. default values:
 - digits = 6
 - step = 30
 - algo = SHA1

options
    -n | --name      the name of the new record REQUIRED
    -f | --file      the desired file to store the new record in
    -s | --secret    a valid BASE43 string REQUIRED
    -a | --algo      the desired algorithm used to generate codes with
    -d | --digits    number of digits to generate for the codes
    -t | -p | --step | --period
                     the step between generating new codes
    -i | --issuer    the issuer that the code is for
    -u | --username  the username associated with the codes

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified")
            },
            "add-url" => {
                println!("add-url [options]

adds a new record to a totp file using url format. default values if the fields
are not found in the url
 - digits = 6
 - step = 30
 - algo = SHA1

options
    -f | --file  the desired file to store the new record in
    --url        the url to parse REQUIRED
    -n | --name  the name of the new record. overrides the url value if
                 present
    -v | --view  will not add the record and only show the details of the
                 record

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified")
            },
            "add-gauth" => {
                println!("add-gauth [options]

adds a new record to a totp file with google authenticator defaults. it will 
assign certain values to a specified default for the application.
 - digits = 6
 - step = 30
 - algo = SHA1

options
    -n | --name    the name of the record. default is \"Unknown\"
    -f | --file    the desired file to store the new record in
    -s | --secret  the secret to assign the new record REQUIRED

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified")
            },
            "view" => {
                println!("view [options]

views records of a totp file

options
    -n | --name  name of a specific record to view
    -f | --file  the desired file to view records from

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified")
            },
            "edit" => {
                println!("edit [options]

updates a specific record to the desired values

options
    -n | --name      the name of the record to update REQUIRED
    -f | --file      the desired file to update a record in
    -s | --secret    updates secret on record
    -a | --algo      updates algo on record
    -d | --digits    updates digits on record
    -t | --step | -p | --period
                     updates step on record
    -i | --issuer    updates issuer on record
    -u | --username  updates username on record

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified")
            },
            "rename" => {
                println!("rename [options]

renames a record to a new name

options
    -f | --file  the dsired file to rename a record in
    --original   the original name of the record REQUIRED
    --renamed    the new name of the record REQUIRED

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified");
            },
            "drop" => {
                println!("drop [options]

drops a record from a totp file

options
    -f | --file  the desired file to drop a record from
    -n | --name  the name of the record to drop REQUIRED

note:
the user will be prompted to enter in a secret used to encrypt the file 
specified")
            },
            _ => {
                let mut msg = String::from("unknown operation provided \"");
                msg.push_str(&op);
                msg.push('"');

                return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                    .with_message(msg))
            }
        }
    } else {
        println!("help [operation]

operations

    codes      prints generated codes to the terminal
    new        generates a new encrypted totp file
    add        adds a new record to a totp file
    add-url    adds a new record to a totp file using url format
    add-guath  adds a new record to a totp file with google authenticator
               defaults
    view       views records of a totp file
    edit       updates a specific record to the desired values
    rename     renames a record to a new name
    drop       drops a record from a totp file")
    }

    Ok(())
}