msg = """{
    "round_id": "1",
    "round_description": "HackWasm Berlin",
	"maci_denom": "uDORA",
	"parameters": {
		"state_tree_depth": "2",
		"int_state_tree_depth": "1",
		"message_batch_size": "5",
		"vote_option_tree_depth": "1"
	},
	"coordinator": {
		"x": "3557592161792765812904087712812111121909518311142005886657252371904276697771",
		"y": "4363822302427519764561660537570341277214758164895027920046745209970137856681"
	},
	"process_vkey": {
		"vk_alpha1": "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926",
		"vk_beta_2": "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8",
		"vk_gamma_2": "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
		"vk_delta_2": "22271cda8c78ebfb3b15c4c6cde9e05231f0a0d90ab80e641ffe7b16233205472864fb9deedbbe0855d09deee7f3b51729c8e6b7bdd72e8b98def08e5c9029b119eef68c7b12c16a9f39f911aa6905c6bdae9e7412c68f6b0bef1e96377f3a732978c67e4e4ba33564d910e2a15325a9974acf1d3c8a187069426e4f0963485f",
		"vk_ic0": "054c5d7a72add567d812099efec32628d4fde2bc1efd867e2e38b3d369aca16a2837e4ed0ae0a93ae6ff09866b87bb80d014dfff263b0833fefd182ef034e663",
		"vk_ic1": "0493f44e067e7c3100565e6a4119f5f10a4dce5f714bc88aabce04b4770c48ba07b9ec8a559bcb7176d7bfe8bbe8ae2731c7c7683911dca2fc9709884db50b83"
	},
	"qtr_lib": {
		"zeros": ["0", "14655542659562014735865511769057053982292279840403315552050801315682099828156", "19261153649140605024552417994922546473530072875902678653210025980873274131905", "21526503558325068664033192388586640128492121680588893182274749683522508994597", "20017764101928005973906869479218555869286328459998999367935018992260318153770", "16998355316577652097112514691750893516081130026395813155204269482715045879598", "2612442706402737973181840577010736087708621987282725873936541279764292204086", "17716535433480122581515618850811568065658392066947958324371350481921422579201", "17437916409890180001398333108882255895598851862997171508841759030332444017770"]
	},
	"tally_vkey": {
		"vk_alpha1": "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926",
		"vk_beta_2": "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8",
		"vk_gamma_2": "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
		"vk_delta_2": "2be07265a2a43e683a7ac880a23ea9f34588c440e9df12e712b9e830c5263b8f1cebe7adb70a095f552063c31a9d9a5051c9d4998b9e3b336ffa79ea00da373822817d0b7fc2294c9d3e3974fd5a7a8a01435c4dff095d588c2a3f73737d19b51349dbdca1b6fcd3b7d929a97e06fe55041a062c550d8f7ed3d912f8ed47d2ef",
		"vk_ic0": "1bc1a1a3444256469c07cd6f4d1cfd9f7c9ddce596a306e0af077ca9e9c0fe9602db2a9aecef76a9dc4c19bf88c0099b04fc75410cc9004f0966440825e3790a",
		"vk_ic1": "05b8b475f2bfedba4fa04ab1972006da9764c2c3e6fb65d6dd0aac938fd298112a560e13770b06a3f709a49fddf016331ea205fa125026993f6666eff69f4def"
	}
}"""

res = msg.replace("\n", "")
print(res)
