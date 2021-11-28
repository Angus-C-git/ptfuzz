# version import


'''
:::::::::::::::::::::::: [PTFUZZ: internals] ::::::::::::::::::::::::
 		   
process   --- pid --> begin_trace(pdi) --> set_traps(blocks) --
       												 	      | 	
															  |
				 					 <--- handle_trap() <------
										  |	   ^  |
										  |___/   |
										          |
												  V
									   update_coverage()

_ begin_trace(tracee) _

	+ Handels starting trace on tracee

_ set_anchors(blocks) _

	+ Sets breakpoints at the start of 
	  each block in a program

_ handle_trap() _

	+ Primary utility method for fuzzing
	+ Recives trap signals from the process
	+ Updates coverage information
	+ Restores register states modified to 
	  set the blocks breakpoints
	+ The coverage handler higher up
	 takes care of saving the progressing
	 input to a corpus 

'''
