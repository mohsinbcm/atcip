pragma solidity >=0.4.25 <0.6.0;

contract ATCIP
{
     //Set of States
    enum StateType { Create, InsurenotVerified, Insured, ClaimInitiated, TermVoid, NoClaim}
    
    //List of properties
    StateType public  State;
    enum calamityEnum { None, Drought, Flood}
    calamityEnum public calamity;

    address public admin;
    address public insurance_provider;
    address public feeder;
    address public Viewer;

    string public policy_no;
    string public start_date;
    string public end_date;
    string public sum_insured;
    string public interest;
    string public premium;
    string public coordinates;
    int public coverage;

    string public verifyPolicyDuration;
    string public getWeatherData;

    // constructor function
    constructor(string policyno, string stdt, string endt, string suminsured, string intrst, string prm, string coords) public
    {
        admin = msg.sender;
        policy_no = policyno;
        start_date = stdt;
        end_date = endt;
        sum_insured = suminsured;
        interest = intrst;
        premium = prm;
        coordinates = coords;
        State = StateType.Create;
    }

    // call this function to send a request
    function verifyPolicyDuration(bool verificationData) public
    {
        if(insurance_provider != msg.sender){
            revert();
        }
        if(verificationData){
            State = StateType.Insured;
        }else{
            State = StateType.TermVoid;
        }
    }

    // call this function to send a response
    function getWeatherData(calamityEnum in_calamity, int coverge) public
    {
        calamity = in_calamity;
        if(calamity == calamityEnum.None){
            State = StateType.NoClaim;
        }else{
            coverage = coverge;
            if(State == StateType.Insured){
                State = StateType.ClaimInitiated;
            }else{
                State = StateType.InsurenotVerified;
            }
        }
        // call ContractUpdated() to record this action
    }

    function toInsuranceProvider(address ins_pro, address feedr) public
    {
        if (State == StateType.Create)
        {
            State = StateType.InsurenotVerified;
        }
        insurance_provider=ins_pro;
        feeder = feedr;
    }
}