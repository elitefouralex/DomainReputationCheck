INSTRUCTIONS:

This code was written on and for debian based linux distros. My main ones are ubuntu and raspbian. 
For this reason the code is ran in bash with python3. 
Inorder for this script to run you must first put your API keys in the .bashrc file in your home directory, 
this is signified by the "os.environ.get" in the variables stated at the beginning of the code.
You can name them whatever you want, just make sure to this is done in .bashrc . 
To do this, do sudo nano .bashrc and authenticate, once there go to an open spot and type
export myapikey = "thisiswheretheapikeywouldgo" 
or something along those lines, you cane name them whatever but the export is mandatory. make as many as you want.
make sure to save this and restart for linux to save it and be able to use it in the code.
